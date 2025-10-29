import json
import os
import subprocess
from datetime import datetime
import traceback 

import boto3
import botocore.exceptions

s3_client = boto3.client("s3")
scan_time = datetime.now().isoformat()

def run_command(command):
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    return (result.returncode, result.stdout.decode("utf-8"), result.stderr.decode("utf-8"))

def definition_upload():
    """Downloads latest ClamAV definitions, packages them, and uploads to S3."""
    try:
        # Create the directory to store the definitions
        os.makedirs("/tmp/clamav/database", exist_ok=True)
        print("Downloading latest ClamAV definitions...")

        # Pull the latest definitions using freshclam
        user_id = run_command("id --user")[1].strip()
        clamav_config = os.environ.get("LAMBDA_TASK_ROOT", "/var/task") + "/freshclam.conf"
        code, out, err = run_command(
            f'freshclam --verbose --user {user_id} --config-file="{clamav_config}"'
        )
        print("Freshclam stdout:", out)
        if err: print("Freshclam stderr:", err)
        if code != 0: raise Exception(f"Freshclam failed with exit code {code}")

        print("Archiving definitions...")
        # Archive the definitions
        run_command(
            "tar --create --gzip --verbose --file=/tmp/clamav/clamav.tar.gz -C /tmp/clamav/database ."
        )

        # Upload the definitions to S3
        bucket_name = os.environ.get("CLAMAV_DEFINITON_BUCKET_NAME")
        if not bucket_name:
            raise ValueError("CLAMAV_DEFINITON_BUCKET_NAME environment variable not set.")

        print(f"Uploading clamav.tar.gz to {bucket_name}...")
        s3_client.upload_file("/tmp/clamav/clamav.tar.gz", bucket_name, "clamav.tar.gz")
        print("Definitions uploaded successfully.")

    except botocore.exceptions.ClientError as e:
        print(f"S3 Error during definition upload: {e}")
        raise
    except Exception as e:
        print(f"Error during definition upload: {e}")
        raise

def definition_download():
    os.makedirs("/tmp/clamav/database", exist_ok=True)
    bucket_name = os.environ.get("CLAMAV_DEFINITON_BUCKET_NAME")
    if not bucket_name:
        raise ValueError("CLAMAV_DEFINITON_BUCKET_NAME environment variable not set.")
    s3_client.download_file(bucket_name, "clamav.tar.gz", "/tmp/clamav/clamav.tar.gz")
    print("Successfully downloaded ClamAV definitions from S3.")
    run_command("tar --extract --gzip --verbose --file=/tmp/clamav/clamav.tar.gz -C /tmp/clamav/database")
    print("Successfully extracted ClamAV definitions.")

def run_scan(file_path):
    """
    Runs the clamscan command on a file.
    Returns: A tuple of (status, detail)
             e.g., ("clean", None) or ("infected", "Win.Test.EICAR_HDB-1")
    """
    exit_code, stdout, stderr = run_command(
        f"clamscan --database=/tmp/clamav/database \"{file_path}\""
    )
    
    print(stdout)
    if stderr:
        print(f"ClamAV stderr: {stderr}")
    
    if exit_code == 0:
        return ("clean", None)
    
    if exit_code == 1:
        # Parse stdout for the virus name
        virus_name = "Unknown"
        for line in stdout.split('\n'):
            if line.strip().endswith(" FOUND"):
                try:
                    # Parse "filename: virus-name FOUND"
                    virus_name = line.split(': ')[1].replace(' FOUND', '').strip()
                    break # Found it
                except Exception:
                    pass # Failed to parse, will use "Unknown"
        return ("infected", virus_name)
    
    # ClamAV returned an error code (like 2)
    raise Exception(f"ClamAV scan error. Exit code: {exit_code}. STDERR: {stderr}")

def update_tags(bucket_name: str, object_key: str, status: str, detail: str = None):
    """
    Adds tags for the result of a file scan to an object.
    'status' is "clean", "infected", or "error".
    'detail' is the virus name or error message.
    """
    try:
        response = s3_client.get_object_tagging(Bucket=bucket_name, Key=object_key)
        tags = response.get("TagSet", [])
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchTaggingSet':
            tags = []
        else:
            print(f"Failed to get tags for {object_key}: {e}")
            tags = [] # Default to empty list on other errors

    additional_tags = {
        "scan-result": status,
        "scan-time": scan_time,
    }

    if status == "infected" and detail:
        additional_tags["virus-name"] = detail
    elif status == "error" and detail:
        # S3 tags cannot contain newlines
        safe_error = detail.replace('\n', ' ').replace('\r', ' ')
        additional_tags["scan-error"] = safe_error[:250]

    # Remove any existing tags with the same key
    tags_to_keep = [t for t in tags if t['Key'] not in additional_tags]
    tags_to_keep.extend([{"Key": key, "Value": value} for key, value in additional_tags.items()])

    s3_client.put_object_tagging(
        Bucket=bucket_name,
        Key=object_key,
        Tagging={"TagSet": tags_to_keep},
    )

def move_and_tag_files(destination_bucket: str, scan_results_map: dict):
    """
    Moves files and applies individual tags based on the scan_results_map.
    scan_results_map = {
        "key1": ("clean", None),
        "key2": ("infected", "EICAR-Test-File"),
        "key3": ("error", "ClamAV scan error")
    }
    """
    landing_bucket_name = os.environ["LANDING_BUCKET_NAME"]
    
    for object_key, (status, detail) in scan_results_map.items():
        try:
            print(f"Moving {object_key} to {destination_bucket} with status: {status}")
            copy_source = {"Bucket": landing_bucket_name, "Key": object_key}
            
            s3_client.copy_object(
                Bucket=destination_bucket, CopySource=copy_source, Key=object_key
            )
            s3_client.delete_object(
                Bucket=landing_bucket_name, Key=object_key
            )
            
            # Tag the object in its new location
            update_tags(
                bucket_name=destination_bucket,
                object_key=object_key,
                status=status,
                detail=detail
            )
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] in ['404', 'NoSuchKey']:
                print(f"File {object_key} was already processed by a concurrent invocation.")
            else:
                print(f"FATAL: Could not move or tag {object_key}. Error: {e}")
                traceback.print_exc()

def handler(event, context):
    """
    Main Lambda handler. Checks MODE first.
    If 'definition-upload', runs that task.
    If 'scan', processes the S3 event.
    """
    print("Received event:", event)
    mode = os.environ.get("MODE", "scan")

    # --- CHECK MODE FIRST ---
    if mode == "definition-upload":
        print("Running in definition-upload mode...")
        try:
            definition_upload()
            return {"statusCode": 200, "body": json.dumps({"message": "Definition upload successful."})}
        except Exception as e:
            print(f"Definition upload failed: {e}")
            traceback.print_exc()
            return {"statusCode": 500, "body": json.dumps({"message": f"Definition upload failed: {str(e)}"}) }

    elif mode == "scan":
        print("Running in scan mode...")

        landing_bucket = os.environ.get("LANDING_BUCKET_NAME")
        processed_bucket = os.environ.get("PROCESSED_BUCKET_NAME")
        quarantine_bucket = os.environ.get("QUARANTINE_BUCKET_NAME")

        files_to_process = {}
        folder_keys_to_move = []
        FIVE_GB = 5 * 1024 * 1024 * 1024

        try:
            # Check event structure *before* accessing keys
            if "Records" not in event or not isinstance(event["Records"], list) or len(event["Records"]) == 0 or \
               "s3" not in event["Records"][0] or "object" not in event["Records"][0]["s3"] or \
               "key" not in event["Records"][0]["s3"]["object"]:
                 print("[WARN] Received event does not match expected S3 structure. Ignoring.")
                 return {"statusCode": 200, "body": json.dumps({"message": "Event ignored, invalid structure."})}

            triggering_object_key = event["Records"][0]["s3"]["object"]["key"]

            if not triggering_object_key.endswith('_commit.json'):
                print(f"Ignoring non-commit-file trigger: {triggering_object_key}")
                return {"statusCode": 200, "body": json.dumps({"message": "Trigger ignored."})}

            directory = os.path.dirname(triggering_object_key)
            prefix = directory + "/" if directory else ""

            paginator = s3_client.get_paginator('list_objects_v2')
            for page in paginator.paginate(Bucket=landing_bucket, Prefix=prefix):
                if "Contents" in page:
                    for obj in page["Contents"]:
                        if not obj['Key'].endswith('/'):
                            files_to_process[obj['Key']] = obj['Size']
                        else:
                            folder_keys_to_move.append(obj['Key'])

            if not files_to_process:
                print(f"No data files found in batch prefix: {prefix}. Cleaning up commit file and folders.")
                scan_results_map = {triggering_object_key: ("clean", None)}
                move_and_tag_files(processed_bucket, scan_results_map)
                for key in folder_keys_to_move:
                     print(f"Deleting clean folder object: {key}")
                     try: s3_client.delete_object(Bucket=landing_bucket, Key=key)
                     except Exception as folder_e: print(f"Could not delete folder object {key}: {folder_e}")
                return {"statusCode": 200, "body": json.dumps({"message": "Empty batch processed successfully"})}


            print(f"Processing batch. Prefix: {prefix}. Files: {list(files_to_process.keys())}")

            os.makedirs("/tmp/clamav/scan", exist_ok=True)
            definition_download()

            scan_results_map = {}
            is_batch_infected_or_error = False

            for object_key in files_to_process.keys():
                try:
                    if object_key.endswith('_commit.json'):
                        scan_results_map[object_key] = ("clean", None)
                        continue

                    print(f"Scanning file: {object_key}")
                    local_file_path = f"/tmp/clamav/scan/{os.path.basename(object_key)}"
                    s3_client.download_file(landing_bucket, object_key, local_file_path)

                    status, detail = run_scan(local_file_path)
                    scan_results_map[object_key] = (status, detail)

                    if status == "infected":
                        print(f"INFECTED: {object_key}, Virus: {detail}")
                        is_batch_infected_or_error = True
                    elif status == "error":
                        print(f"ERROR: {object_key} during scan, Detail: {detail}")
                        is_batch_infected_or_error = True
                    else:
                        print(f"CLEAN: {object_key}")

                    os.remove(local_file_path)

                except Exception as e:
                    print(f"ERROR processing {object_key}: {e}")
                    traceback.print_exc()
                    scan_results_map[object_key] = ("error", str(e))
                    is_batch_infected_or_error = True

            if not is_batch_infected_or_error:
                for object_key, size in files_to_process.items():
                    if size > FIVE_GB:
                        print(f"ERROR: File {object_key} size ({size}) exceeds 5GB copy limit.")
                        scan_results_map[object_key] = ("error", "File exceeds 5GB copy limit")
                        is_batch_infected_or_error = True

            if is_batch_infected_or_error:
                print("Batch contains infected, errored, or oversized files. Moving all files to quarantine.")
                move_and_tag_files(quarantine_bucket, scan_results_map)
                for key in folder_keys_to_move:
                    print(f"Moving folder {key} to quarantine")
                    try:
                        s3_client.copy_object(Bucket=quarantine_bucket, CopySource={"Bucket": landing_bucket, "Key": key}, Key=key)
                        s3_client.delete_object(Bucket=landing_bucket, Key=key)
                    except Exception as folder_e: print(f"Could not move folder {key} to quarantine: {folder_e}")

            else:
                print("Batch is clean and within size limits. Moving all files to processed.")
                move_and_tag_files(processed_bucket, scan_results_map)
                for key in folder_keys_to_move:
                    print(f"Deleting clean folder object: {key}")
                    try: s3_client.delete_object(Bucket=landing_bucket, Key=key)
                    except Exception as folder_e: print(f"Could not delete folder object {key}: {folder_e}")

        except Exception as e:
            # Catch-all for *system* errors
            print(f"A system error occurred during batch processing: {e}")
            traceback.print_exc()

            error_results_map = {}
            for key in files_to_process.keys():
                if key not in error_results_map:
                    error_results_map[key] = ("error", str(e))

            if not error_results_map:
                 try:
                     trigger_key = event.get("Records", [{}])[0].get("s3", {}).get("object", {}).get("key", "unknown-trigger-key")
                     error_results_map[trigger_key] = ("error", str(e))
                 except Exception: pass

            print("Moving all known batch files to quarantine due to system error.")
            move_and_tag_files(quarantine_bucket, error_results_map if error_results_map else {})

            for key in folder_keys_to_move:
                print(f"Moving error folder {key} to quarantine")
                try:
                    s3_client.copy_object(Bucket=quarantine_bucket, CopySource={"Bucket": landing_bucket, "Key": key}, Key=key)
                    s3_client.delete_object(Bucket=landing_bucket, Key=key)
                except Exception as folder_e: print(f"Could not move folder {key} to quarantine: {folder_e}")

            return {"statusCode": 500, "body": json.dumps({"message": f"An error occurred: {str(e)}"}) }

        # If scan logic completes successfully
        return {"statusCode": 200, "body": json.dumps({"message": "Batch processed successfully"})}

    else:
        # Handle invalid MODE setting
        print(f"[ERROR] Invalid MODE environment variable: {mode}")
        return {"statusCode": 400, "body": json.dumps({"message": f"Invalid MODE: {mode}"})}