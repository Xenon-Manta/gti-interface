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
CSV_FILE = '/Users/testuser/Downloads/iplist2.csv'
API_KEY = 'KEY HERE'  # Replace with your actual API key
ip_results = []
vt_results = []
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

def send_ip_to_virustotal(ips):
    for ip in ips:
        VT_URL = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
        headers = {
            'x-apikey': API_KEY,
            'Content-Type': 'application/json'
        }
        response = requests.get(VT_URL, headers=headers)
        print(response.text)
        ip_results.append(response.text)
    return ip_results

def main():
    ips = read_ips_from_csv(CSV_FILE)
    print(f"Total IPs loaded: {len(ips)}")
    for i in range(0, len(ips), BATCH_SIZE):
        batch = ips[i:i+BATCH_SIZE]
        print(f"Sending batch {i//BATCH_SIZE + 1} ({len(batch)} IPs)...")
        result = send_ip_to_virustotal(batch)
        print(result)
        
        time.sleep(1)  # Still testing to see how long this should be, not sure yet

if __name__ == "__main__":
    main()
