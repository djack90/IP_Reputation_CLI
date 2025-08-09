import argparse
import csv
import json
import os
import sys
import urllib.parse
import urllib.request
from typing import Iterable, List, Dict

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"

def fetch_abuseipdb_score(ip: str, api_key: str) -> int:
    """Return AbuseIPDB abuse confidence score for the given IP."""
    params = urllib.parse.urlencode({"ipAddress": ip})
    url = f"{ABUSEIPDB_URL}?{params}"
    req = urllib.request.Request(url, headers={"Key": api_key, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        data = json.load(resp)
    return data.get("data", {}).get("abuseConfidenceScore")

def fetch_virustotal_score(ip: str, api_key: str) -> int:
    """Return VirusTotal reputation score for the given IP."""
    url = VT_URL.format(ip=urllib.parse.quote(ip))
    req = urllib.request.Request(url, headers={"x-apikey": api_key})
    with urllib.request.urlopen(req, timeout=10) as resp:
        data = json.load(resp)
    return data.get("data", {}).get("attributes", {}).get("reputation")

def reputation_for_ips(ips: Iterable[str], abuse_key: str, vt_key: str) -> List[Dict[str, int]]:
    """Return reputation scores for a collection of IPs."""
    results = []
    for ip in ips:
        abuse_score = fetch_abuseipdb_score(ip, abuse_key)
        vt_score = fetch_virustotal_score(ip, vt_key)
        results.append({
            "ip": ip,
            "abuse_confidence_score": abuse_score,
            "virustotal_reputation": vt_score,
        })
    return results

def write_csv(rows: List[Dict[str, int]], file_obj) -> None:
    """Write rows to ``file_obj`` as CSV."""
    fieldnames = ["ip", "abuse_confidence_score", "virustotal_reputation"]
    writer = csv.DictWriter(file_obj, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        writer.writerow(row)

def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Query AbuseIPDB and VirusTotal for IP reputations")
    parser.add_argument("input_file", help="File containing IP addresses, one per line")
    args = parser.parse_args(argv)

    abuse_key = os.getenv("ABUSEIPDB_API_KEY")
    vt_key = os.getenv("VT_API_KEY")
    if not abuse_key or not vt_key:
        parser.error("Environment variables ABUSEIPDB_API_KEY and VT_API_KEY must be set")

    with open(args.input_file, "r", encoding="utf-8") as f:
        ips = [line.strip() for line in f if line.strip()]

    rows = reputation_for_ips(ips, abuse_key, vt_key)
    write_csv(rows, sys.stdout)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
