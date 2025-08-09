# IP Reputation CLI

This repository contains a simple command-line interface that queries the
AbuseIPDB and VirusTotal APIs for reputation information about IP addresses.
It reads IPs from a file and prints a CSV with the AbuseIPDB confidence score
and VirusTotal reputation for each address.

## Usage

1. Set the API keys as environment variables:
   ```bash
   export ABUSEIPDB_API_KEY="your-abuseipdb-key"
   export VT_API_KEY="your-virustotal-key"
   ```
2. Create a text file with one IP address per line.
3. Run the tool:
   ```bash
   python ip_reputation.py ips.txt > output.csv
   ```

## Testing

Run the unit tests with:

```bash
python -m unittest
```
