import requests
import json
import time
import os
import csv
from dotenv import load_dotenv
from datetime import datetime
from pathlib import Path
import re

# Load API key
load_dotenv()
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

if not VIRUSTOTAL_API_KEY:
    raise EnvironmentError("VirusTotal API key not found in .env file.")

# Normalize filename (for filesystem safety)
def safe_filename(name):
    return re.sub(r'[^\w\-_.]', '_', name)

# Query VirusTotal
def check_virustotal(target):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{target}" if is_ip(target) \
        else f"https://www.virustotal.com/api/v3/domains/{target}"
    
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return parse_virustotal_response(response.json())
    else:
        return {"error": f"Failed to fetch data for {target}. Status Code: {response.status_code}"}

# Determine if target is IP address
def is_ip(value):
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", value.strip()))

# Parse VirusTotal response
def parse_virustotal_response(data):
    attributes = data.get("data", {}).get("attributes", {})
    
    stats = attributes.get("last_analysis_stats", {})
    analysis_date = attributes.get("last_analysis_date", 0)
    analysis_date_fmt = datetime.utcfromtimestamp(analysis_date).strftime('%Y-%m-%d %H:%M:%S') if analysis_date else "N/A"

    total_votes = attributes.get("total_votes", {})
    malicious_votes = stats.get("malicious", 0)
    suspicious_votes = stats.get("suspicious", 0)

    # Threat level logic
    if malicious_votes >= 5:
        threat_level = "High"
    elif suspicious_votes >= 3:
        threat_level = "Medium"
    else:
        threat_level = "Low"

    return {
        "Target": data.get("data", {}).get("id", "N/A"),
        "Country": attributes.get("country", "N/A"),
        "WHOIS Info": attributes.get("whois", "N/A"),
        "Last Analysis Date": analysis_date_fmt,
        "Reputation Score": attributes.get("reputation", "N/A"),
        "Last Analysis Stats": stats,
        "Total Votes": total_votes,
        "Threat Level": threat_level
    }

# Process list of targets
def process_targets(file_path):
    with open(file_path, newline='') as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            if not row:
                continue
            target = row[0].strip()
            print(f"\nAnalyzing: {target}")
            report = check_virustotal(target)
            filename = f"results_{safe_filename(target)}.json"
            with open(filename, "w") as f:
                json.dump(report, f, indent=4)
            print(f"Saved report to {filename}")
            time.sleep(15)  # Respect VT rate limits (especially for free API)

# Entry point
if __name__ == "__main__":
    targets_csv = "targets.csv"
    if not os.path.exists(targets_csv):
        print(f"File not found: {targets_csv}")
    else:
        process_targets(targets_csv)
