import json
import requests
import os
import csv
import time
from requests_toolbelt.multipart.encoder import MultipartEncoder

# MobSF configuration
SERVER = "http://127.0.0.1:8000"
APIKEY = '76069ab86780246b381c9351e83e3db4d0af0bb5397ba12a2c6a045378d5b318' # REST API KEY goes here 

# Input directory with APKs
APK_DIRECTORY = 'android_apks_folder' #Change this directory if your

# Output directories
OUTPUT_DIR = os.path.join(os.getcwd(), 'analysis_results')
CSV_DIR = os.path.join(OUTPUT_DIR, 'csv_reports')
JSON_DIR = os.path.join(OUTPUT_DIR, 'json_reports')
PDF_DIR = os.path.join(OUTPUT_DIR, 'pdf_reports')
CSV_FILE = os.path.join(CSV_DIR, 'results.csv')

# Create necessary directories
os.makedirs(CSV_DIR, exist_ok=True)
os.makedirs(JSON_DIR, exist_ok=True)
os.makedirs(PDF_DIR, exist_ok=True)

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

def pdf_report(data, filename):
    print("Generating PDF report...")
    headers = {'Authorization': APIKEY}
    data = {"hash": json.loads(data)["hash"]}
    response = requests.post(SERVER + '/api/v1/download_pdf', data=data, headers=headers)
    with open(filename, 'wb') as pdf_file:
        pdf_file.write(response.content)

def save_to_json(result, filename):
    with open(filename, 'w') as jsonfile:
        json.dump(result, jsonfile, indent=4)

def delete(data):
    print("Deleting scan from MobSF...")
    headers = {'Authorization': APIKEY}
    data = {"hash": json.loads(data)["hash"]}
    requests.post(SERVER + '/api/v1/delete_scan', data=data, headers=headers)

def extract_dangerous_permissions(permissions):
    """Extract only permissions with 'dangerous' status"""
    dangerous_perms = {}
    if permissions:
        for perm, details in permissions.items():
            if details.get('status') == 'dangerous':
                dangerous_perms[perm] = details
    return dangerous_perms

def extract_manifest_analysis(manifest_analysis):
    """Extract rule, severity, description from manifest findings"""
    extracted_findings = []
    if manifest_analysis and 'manifest_findings' in manifest_analysis:
        for finding in manifest_analysis['manifest_findings']:
            extracted_finding = {
                'rule': finding.get('rule'),
                'severity': finding.get('severity'),
                'description': finding.get('description')
            }
            extracted_findings.append(extracted_finding)
    return extracted_findings

def extract_code_analysis(code_analysis):
    """Extract 3rd level keys and their metadata from code analysis"""
    extracted_findings = {}
    if code_analysis and 'findings' in code_analysis:
        for finding_key, finding_data in code_analysis['findings'].items():
            if 'metadata' in finding_data:
                extracted_findings[finding_key] = finding_data['metadata']
    return extracted_findings

def extract_permission_mapping(permission_mapping):
    """Extract top level and second level keys from permission mapping"""
    extracted_mapping = {}
    if permission_mapping:
        for top_key, second_level in permission_mapping.items():
            if isinstance(second_level, dict):
                extracted_mapping[top_key] = list(second_level.keys())
            else:
                extracted_mapping[top_key] = second_level
    return extracted_mapping

def process_result_for_csv(result):
    """Process the JSON result to extract only the required fields for CSV"""
    processed_result = result.copy()
    
    # Add dangerous_permissions column (keep original permissions column)
    if 'permissions' in processed_result:
        processed_result['dangerous_permissions'] = extract_dangerous_permissions(processed_result['permissions'])
    
    # Replace manifest_analysis with filtered data
    if 'manifest_analysis' in processed_result:
        processed_result['manifest_analysis'] = extract_manifest_analysis(processed_result['manifest_analysis'])
    
    # Replace code_analysis with filtered data
    if 'code_analysis' in processed_result:
        processed_result['code_analysis'] = extract_code_analysis(processed_result['code_analysis'])
    
    # Replace permission_mapping with filtered data
    if 'permission_mapping' in processed_result:
        processed_result['permission_mapping'] = extract_permission_mapping(processed_result['permission_mapping'])
    
    # Add the specific columns from the appsec section
    appsec_data = result.get('appsec', {})
    processed_result['total_trackers'] = appsec_data.get('total_trackers')
    processed_result['trackers'] = appsec_data.get('trackers')
    processed_result['security_score'] = appsec_data.get('security_score')
    processed_result['app_name'] = result.get('app_name')  # This might be at root level
    processed_result['file_name'] = result.get('file_name')  # This might be at root level
    processed_result['hash'] = result.get('hash')  # This might be at root level
    processed_result['version_name'] = result.get('version_name')  # This might be at root level
    
    return processed_result

def export_to_csv(results, csv_file):
    if not results:
        return
    
    # Process results for CSV
    processed_results = [process_result_for_csv(result) for result in results]
    
    fieldnames = processed_results[0].keys()
    with open(csv_file, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for result in processed_results:
            # Convert complex objects to JSON strings for CSV storage
            csv_row = {}
            for key, value in result.items():
                if isinstance(value, (dict, list)):
                    csv_row[key] = json.dumps(value)
                else:
                    csv_row[key] = value
            writer.writerow(csv_row)

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

        # Save JSON report
        json_filename = os.path.splitext(apk_file)[0] + ".json"
        json_filepath = os.path.join(JSON_DIR, json_filename)
        save_to_json(result, json_filepath)

        # Save PDF report in app-specific directory
        app_name = result.get('app_name', 'Unknown_App')
        package_name = result.get('package_name', 'unknown_package')
        
        # Create app-specific directory for PDF
        app_pdf_dir = os.path.join(PDF_DIR, app_name)
        os.makedirs(app_pdf_dir, exist_ok=True)
        
        # Save PDF with package name
        pdf_filename = package_name + ".pdf"
        pdf_filepath = os.path.join(app_pdf_dir, pdf_filename)
        pdf_report(resp, pdf_filepath)

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
print(f"PDF reports saved to:      {PDF_DIR}")
print(f"CSV file saved to:         {CSV_FILE if results else 'N/A'}")
print(f"Total time elapsed:        {minutes} min {seconds} sec")
print("======================================")