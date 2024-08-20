import requests
import json
from datetime import datetime, timedelta

# Prisma Cloud API endpoints
BASE_URL = "https://api3.prismacloud.io"
LOGIN_URL = f"{BASE_URL}/login"
QUERY_URL = f"{BASE_URL}/v2/alert"

# Your Prisma Cloud credentials
ACCESS_KEY = "d9071b9f-8a3d-4f5f-87e8-ebc4fe857518"
SECRET_KEY = "3taQez3V1Na7X3HE0lPRK53JeBs="

# Authentication
def get_token():
    headers = {"Content-Type": "application/json"}
    data = {
        "username": ACCESS_KEY,
        "password": SECRET_KEY
    }
    response = requests.post(LOGIN_URL, headers=headers, data=json.dumps(data))
    return response.json()["token"]
    

# Query for IAC Misconfiguration violations
def get_iac_misconfigurations(token):
    headers = {
        "Content-Type": "application/json",
        "x-redlock-auth": token
    }
    
    # Set time range for the last 30 days
    time_range = {
        "type": "relative",
        "value": {
            "amount": 30,
            "unit": "day"
        }
    }
    
    payload = {
        "query": "config from cloud.resource where cloud.type = 'iac'",
        "timeRange": time_range,
        "limit": 1000  # Adjust as needed
    }
    
    response = requests.post(QUERY_URL, headers=headers, data=json.dumps(payload))
    return response.json()

# Save violations to CSV
def save_to_csv(violations):
    filename = f"iac_violations_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    with open(filename, 'w', newline='') as csvfile:
        fieldnames = ['Resource Name', 'Resource Type', 'Policy Name', 'Severity', 'Description']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for violation in violations:
            writer.writerow({
                'Resource Name': violation.get('resource', {}).get('name', 'N/A'),
                'Resource Type': violation.get('resource', {}).get('type', 'N/A'),
                'Policy Name': violation.get('policy', {}).get('name', 'N/A'),
                'Severity': violation.get('severity', 'N/A'),
                'Description': violation.get('description', 'N/A')
            })
    print(f"CSV file saved: {filename}")

# Save full API response to JSON
def save_to_json(response):
    filename = f"api_response_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, 'w') as jsonfile:
        json.dump(response, jsonfile, indent=2)
    print(f"JSON file saved: {filename}")

# Main function
def main():
    token = get_token()
    response = get_iac_misconfigurations(token)
    
    print("API Response:")
    print(json.dumps(response, indent=2))
    
    # Save full API response to JSON
    save_to_json(response)
    
    if 'items' in response:
        total_violations = response.get('totalRows', 0)
        print(f"Total IAC Misconfiguration violations found: {total_violations}")
        
        if total_violations > 0:
            save_to_csv(response['items'])
            
            for violation in response['items']:
                print(f"Resource Name: {violation.get('resource', {}).get('name', 'N/A')}")
                print(f"Resource Type: {violation.get('resource', {}).get('type', 'N/A')}")
                print(f"Policy Name: {violation.get('policy', {}).get('name', 'N/A')}")
                print(f"Severity: {violation.get('severity', 'N/A')}")
                print(f"Description: {violation.get('description', 'N/A')}")
                print("---")
        else:
            print("No violations found.")
    else:
        print("No 'items' key found in the API response. Check for error messages or unexpected response format.")
        if 'message' in response:
            print(f"Error message: {response['message']}")

if __name__ == "__main__":
    main()
