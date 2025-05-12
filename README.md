# VirusTotal Domain & IP Analysis Script

This Python script allows you to analyze a list of domains or IP addresses using Virus Total.
It checks their reputation and threat level, then saves a detailed JSON report for each target.

---

## Features

- Automatically determines if the target is a domain or IP address
- Queries VirusTotal API for threat intelligence
- Parses analysis stats and assigns a threat level
- Saves results as individual JSON files
- Respects API rate limits
- Uses `.env` for secure API key management

---

## Requirements

- Python 3.7+
- A free VirusTotal API key

---

## Installation

1. **Clone the repo**
   ```bash
   git clone https://github.com/yourusername/virustotal-analysis.git
   cd virustotal-analysis
