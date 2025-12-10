import json
import os
import subprocess
import uuid
import yaml
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

    # This prevents /tmp from filling up on warm starts
    print("Cleaning up /tmp directory...")
    run_command("rm -rf /tmp/clamav")

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
        additional_tags["virus-name"] = str(detail)[:250]
    elif status == "error" and detail:
        # S3 tags cannot contain newlines, carriage returns, or tabs.
        safe_error = str(detail).replace('\n', ' ').replace('\r', ' ').replace('\t', ' ').strip()

        while "  " in safe_error:
            safe_error = safe_error.replace("  ", " ")
            
        if not safe_error:
            safe_error = "UnknownError"
        additional_tags["scan-error"] = safe_error[:250]

    # Remove any existing tags with the same key
    tags_to_keep = [t for t in tags if t['Key'] not in additional_tags]
    tags_to_keep.extend([{"Key": key, "Value": value} for key, value in additional_tags.items()])

    s3_client.put_object_tagging(
        Bucket=bucket_name,
        Key=object_key,
        Tagging={"TagSet": tags_to_keep},
    )

def get_destination_key(original_key: str, batch_prefix: str, new_prefix: str = None):
    """
    If new_prefix is provided (for partners), replaces the batch_prefix with new_prefix.
    Otherwise (for UI), keeps the original key structure.
    """
    if new_prefix:
        # Example: original="partners/p1/incoming/file.csv", batch_prefix="partners/p1/incoming/"
        # filename="file.csv", result="new_table/new_db/date/uuid/file.csv"
        filename = original_key.replace(batch_prefix, "")
        return f"{new_prefix}{filename}"
    return original_key

def move_and_tag_files(destination_bucket: str, scan_results_map: dict, batch_prefix: str, new_prefix: str = None):
    """
    Moves files and applies individual tags based on the scan_results_map.
    If new_prefix is set (partner upload), constructs the new path structure.
    Ensures _commit.json is moved LAST to prevent downstream race conditions.
    scan_results_map = {
        "key1": ("clean", None),
        "key2": ("infected", "EICAR-Test-File"),
        "key3": ("error", "ClamAV scan error")
    }
    """
    landing_bucket_name = os.environ["LANDING_BUCKET_NAME"]

    # Sort keys to ensure _commit.json moves last ---
    sorted_keys = sorted(scan_results_map.keys(), key=lambda k: k.endswith('_commit.json'))
    
    for object_key in sorted_keys:
        status, detail = scan_results_map[object_key]

        try:
            # Determine the new key structure
            dest_key = get_destination_key(object_key, batch_prefix, new_prefix)
            print(f"Moving {object_key} to {destination_bucket}/{dest_key} with status: {status}")
            
            copy_source = {"Bucket": landing_bucket_name, "Key": object_key}

            s3_client.copy_object(
                Bucket=destination_bucket, CopySource=copy_source, Key=dest_key
            )
            s3_client.delete_object(
                Bucket=landing_bucket_name, Key=object_key
            )
            
            update_tags(
                bucket_name=destination_bucket,
                object_key=dest_key,
                status=status,
                detail=detail)
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] in ['404', 'NoSuchKey']:
                print(f"File {object_key} was already processed by a concurrent invocation.")
            else:
                print(f"FATAL: Could not move or tag {object_key}. Error: {e}")
                traceback.print_exc()

def validate_and_get_partner_path(bucket, batch_prefix, files_in_batch):
    """
    New behavior: Use co-located _commit.json only.
    - Open commit.json
    - Ensure it parses and is non-null
    - Find either 'yaml_key' or 'data_key' (error if neither)
    - Return the directory prefix of that key (everything except filename),
      ensuring it ends with '/'
    """
    print("Partner upload detected. Resolving prefix from commit.json...")

    # Find commit file in the same folder
    commit_key = None
    for key in files_in_batch:
        if key.endswith("_commit.json"):
            commit_key = key
            break

    if not commit_key:
        raise Exception("Partner upload missing required '_commit.json' file.")

    # Download and parse commit
    local_commit_path = f"/tmp/{os.path.basename(commit_key)}"
    s3_client.download_file(bucket, commit_key, local_commit_path)

    try:
        with open(local_commit_path, 'r') as cf:
            commit_json = json.load(cf)
    except Exception as e:
        raise Exception(f"Invalid or unreadable _commit.json: {e}")

    if not commit_json:
        raise Exception("_commit.json is empty or null.")

    # Prefer yaml_key, otherwise data_key
    candidate_key = commit_json.get("yaml_key") or commit_json.get("data_key")
    if not candidate_key:
        raise Exception("_commit.json missing both 'yaml_key' and 'data_key'.")

    # Extract directory prefix (everything except filename)
    dir_prefix = os.path.dirname(candidate_key)
    dir_prefix = (dir_prefix + "/") if dir_prefix and not dir_prefix.endswith("/") else dir_prefix

    if not dir_prefix:
        raise Exception("Could not derive directory prefix from commit keys.")

    print(f"Commit-derived partner prefix: {dir_prefix}")
    return dir_prefix

def handler(event, context):
    """
    Main Lambda handler. 
    Checks if triggered by EventBridge for updates, or S3 for scanning.
    """
    print("Received event:", event)
    
    # --- Check for EventBridge Scheduled Update ---
    # If the event contains {"action": "definition-upload"}, force that mode.
    if event.get("action") == "definition-upload":
        print("EventBridge trigger detected. Forcing definition-upload mode.")
        mode = "definition-upload"
    else:
        # Otherwise, fallback to the environment variable
        mode = os.environ.get("MODE", "scan")

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

            is_partner_upload = prefix.startswith("partners/")
            new_partner_prefix = None

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
                move_and_tag_files(processed_bucket, scan_results_map, prefix, None)
                for key in folder_keys_to_move:
                     print(f"Deleting clean folder object: {key}")
                     try: s3_client.delete_object(Bucket=landing_bucket, Key=key)
                     except Exception as folder_e: print(f"Could not delete folder object {key}: {folder_e}")
                return {"statusCode": 200, "body": json.dumps({"message": "Empty batch processed successfully"})}


            print(f"Processing batch. Prefix: {prefix}. Files: {list(files_to_process.keys())}")


            definition_download()
            os.makedirs("/tmp/clamav/scan", exist_ok=True)

            scan_results_map = {}
            is_batch_infected_or_error = False

            for object_key in files_to_process.keys():
                try:

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

            # Validate Metadata after successful scan, only for partners
            if not is_batch_infected_or_error and is_partner_upload:
                try:
                    new_partner_prefix = validate_and_get_partner_path(landing_bucket, files_to_process.keys())
                except Exception as e:
                    print(f"Metadata validation failed: {e}")
                    is_batch_infected_or_error = True
                    
                    # Find the metadata file key to tag it with the specific error
                    meta_key = next((k for k in files_to_process.keys() if k.endswith("metadata.yaml")), None)
                    if meta_key:
                        scan_results_map[meta_key] = ("error", str(e))
                    else:
                         print("Could not find metadata file to tag error.")

            if is_batch_infected_or_error:
                print("Batch contains infected, errored, or oversized files. Moving all files to quarantine.")
                move_and_tag_files(quarantine_bucket, scan_results_map, prefix, None)

                for key in folder_keys_to_move:
                    print(f"Moving folder {key} to quarantine")
                    try:
                        s3_client.copy_object(Bucket=quarantine_bucket, CopySource={"Bucket": landing_bucket, "Key": key}, Key=key)
                        s3_client.delete_object(Bucket=landing_bucket, Key=key)
                    except Exception as folder_e: print(f"Could not move folder {key} to quarantine: {folder_e}")

            else:
                print("Batch is clean and within size limits. Moving all files to processed.")
                move_and_tag_files(processed_bucket, scan_results_map, prefix, new_partner_prefix)

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
            move_and_tag_files(quarantine_bucket, error_results_map if error_results_map else {}, prefix if 'prefix' in locals() else "", None)

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