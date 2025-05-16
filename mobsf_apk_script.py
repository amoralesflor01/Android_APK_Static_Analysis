import json
import requests
import os
import csv
import time
from requests_toolbelt.multipart.encoder import MultipartEncoder

# MobSF configuration
SERVER = "http://127.0.0.1:8000"
APIKEY = '1234567890' # REST API KEY goes here 

# Input directory with APKs
APK_DIRECTORY = 'android_apks_folder' #Change this directory if your

# Output directories
OUTPUT_DIR = os.path.join(os.getcwd(), 'analysis_results')
CSV_DIR = os.path.join(OUTPUT_DIR, 'csv_reports')
JSON_DIR = os.path.join(OUTPUT_DIR, 'json_reports')
CSV_FILE = os.path.join(CSV_DIR, 'results.csv')

# Create necessary directories
os.makedirs(CSV_DIR, exist_ok=True)
os.makedirs(JSON_DIR, exist_ok=True)

def upload(file):
    print(f"Uploading file: {file}")
    multipart_data = MultipartEncoder(fields={'file': (file, open(file, 'rb'), 'application/octet-stream')})
    headers = {'Content-Type': multipart_data.content_type, 'Authorization': APIKEY}
    response = requests.post(SERVER + '/api/v1/upload', data=multipart_data, headers=headers)
    return response.text

def scan(data):
    print("Scanning file...")
    post_dict = json.loads(data)
    headers = {'Authorization': APIKEY}
    response = requests.post(SERVER + '/api/v1/scan', data=post_dict, headers=headers)
    return response.text

def json_resp(data):
    print("Generating JSON report...")
    headers = {'Authorization': APIKEY}
    data = {"hash": json.loads(data)["hash"]}
    response = requests.post(SERVER + '/api/v1/report_json', data=data, headers=headers)
    return json.loads(response.text)

def save_to_json(result, filename):
    with open(filename, 'w') as jsonfile:
        json.dump(result, jsonfile, indent=4)

def delete(data):
    print("Deleting scan from MobSF...")
    headers = {'Authorization': APIKEY}
    data = {"hash": json.loads(data)["hash"]}
    requests.post(SERVER + '/api/v1/delete_scan', data=data, headers=headers)

def export_to_csv(results, csv_file):
    fieldnames = results[0].keys()
    with open(csv_file, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

# Start timing
start_time = time.time()

# Collect APK files
if not os.path.exists(APK_DIRECTORY):
    print(f"ERROR: Directory not found -> {APK_DIRECTORY}")
    exit(1)

apk_files = [f for f in os.listdir(APK_DIRECTORY) if f.endswith('.apk')]

if not apk_files:
    print(f"No APK files found in: {APK_DIRECTORY}")
    exit(1)

print(f"Found {len(apk_files)} APK file(s) to analyze.\n")

results = []
processed_count = 0

for i, apk_file in enumerate(apk_files, 1):
    print(f"[{i}/{len(apk_files)}] Processing: {apk_file}")
    apk_path = os.path.join(APK_DIRECTORY, apk_file)

    try:
        resp = upload(apk_path)
        scan(resp)
        result = json_resp(resp)

        json_filename = os.path.splitext(apk_file)[0] + ".json"
        json_filepath = os.path.join(JSON_DIR, json_filename)
        save_to_json(result, json_filepath)

        results.append(result)
        processed_count += 1
        delete(resp)

    except Exception as e:
        print(f"Error processing {apk_file}: {e}")
        continue

# Export results to CSV
if results:
    export_to_csv(results, CSV_FILE)
    print(f"\nCSV summary saved to: {CSV_FILE}")
else:
    print("\nNo results to export.")

# End timing
end_time = time.time()
elapsed_time = end_time - start_time
minutes = int(elapsed_time // 60)
seconds = int(elapsed_time % 60)

# Summary
print("\n========== Analysis Summary ==========")
print(f"Total APKs found:          {len(apk_files)}")
print(f"Successfully processed:    {processed_count}")
print(f"JSON reports saved to:     {JSON_DIR}")
print(f"CSV file saved to:         {CSV_FILE if results else 'N/A'}")
print(f"Total time elapsed:        {minutes} min {seconds} sec")
print("======================================")
