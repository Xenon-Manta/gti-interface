#!/usr/bin/env python3
# Short automation script design to rapidly ingest IPs to VirusTotal
# Items you need for this to work:
# 1. Sudo access to your Laptop with an internet connection
# 2. A CSV file with IPs (one or more per line, separated by commas)
# 3. A VirusTotal API key with access to the batch endpoint
# 4. Python 3 with 'requests' library installed (pip install requests)
# A new revision will be released to this soon with a FrontEnd GUI that can run locally or on a server
# Script to read IPs from a CSV and send to VirusTotal in batches of 990
import csv, requests, time

CSV_FILE = '/Users/testuser/Documents/ip.csv'
API_KEY = 'YOUR_VIRUSTOTAL_API_KEY'  # Replace with your actual API key
VT_URL = 'https://www.virustotal.com/api/v3/ip_addresses/batch'
BATCH_SIZE = 990

def read_ips_from_csv(csv_file):
    ips = []
    with open(csv_file, newline='') as f:
        reader = csv.reader(f)
        for row in reader:
            for item in row:
                item = item.strip()
                if item:
                    ips.append(item)
    return ips

def send_batch_to_virustotal(ip_batch):
    headers = {
        'x-apikey': API_KEY,
        'Content-Type': 'application/json'
    }
    data = {"ips": ip_batch}
    response = requests.post(VT_URL, headers=headers, json=data)
    if response.status_code == 200:
        print(f"Batch of {len(ip_batch)} IPs sent successfully.")
        return response.json()
    else:
        print(f"Error: {response.status_code} - {response.text}")
        return None

def main():
    ips = read_ips_from_csv(CSV_FILE)
    print(f"Total IPs loaded: {len(ips)}")
    for i in range(0, len(ips), BATCH_SIZE):
        batch = ips[i:i+BATCH_SIZE]
        print(f"Sending batch {i//BATCH_SIZE + 1} ({len(batch)} IPs)...")
        result = send_batch_to_virustotal(batch)
        time.sleep(1)  # Still testing to see how long this should be, not sure yet

if __name__ == "__main__":
    main()
