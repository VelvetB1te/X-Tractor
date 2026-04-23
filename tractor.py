#!/usr/bin/env python3
"""
IOC Extractor - Enhanced PCAP Analysis Tool
Extracts Indicators of Compromise from PCAP files with VirusTotal enrichment.
"""

import pyshark
import argparse
import csv
import json
import re
import hashlib
import time
import sys
import os
import requests
from datetime import datetime
from collections import defaultdict


# ──────────────────────────────────────────────
#  Utility
# ──────────────────────────────────────────────

def format_timestamp(ts: datetime) -> str:
    return ts.strftime("%d/%m/%Y %I:%M:%S %p")


def validate_pcap(path: str) -> None:
    """Validate that the PCAP file exists and is readable."""
    if not os.path.exists(path):
        print(f"[ERROR] File not found: {path}")
        sys.exit(1)
    if not os.path.isfile(path):
        print(f"[ERROR] Path is not a file: {path}")
        sys.exit(1)
    if not os.access(path, os.R_OK):
        print(f"[ERROR] File is not readable: {path}")
        sys.exit(1)
    if os.path.getsize(path) == 0:
        print(f"[ERROR] File is empty: {path}")
        sys.exit(1)


# ──────────────────────────────────────────────
#  VirusTotal Enrichment
# ──────────────────────────────────────────────

VT_BASE = "https://www.virustotal.com/api/v3"

def vt_lookup(ioc: str, ioc_type: str, api_key: str, verbose: bool = False) -> dict:
    """
    Query VirusTotal for a single IOC.
    ioc_type: 'ip', 'domain', 'url', 'hash'
    Returns a dict with reputation info or error.
    """
    headers = {"x-apikey": api_key}
    endpoint_map = {
        "ip":     f"{VT_BASE}/ip_addresses/{ioc}",
        "domain": f"{VT_BASE}/domains/{ioc}",
        "url":    f"{VT_BASE}/urls/{requests.utils.quote(ioc, safe='')}",
        "hash":   f"{VT_BASE}/files/{ioc}",
    }

    url = endpoint_map.get(ioc_type)
    if not url:
        return {"error": f"Unsupported IOC type: {ioc_type}"}

    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            return {
                "malicious":  stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless":   stats.get("harmless", 0),
                "reputation": data.get("reputation", "N/A"),
                "country":    data.get("country", "N/A"),
            }
        elif resp.status_code == 404:
            return {"error": "Not found in VirusTotal"}
        elif resp.status_code == 429:
            if verbose:
                print("[VT] Rate limit hit — waiting 60s...")
            time.sleep(60)
            return vt_lookup(ioc, ioc_type, api_key, verbose)
        else:
            return {"error": f"HTTP {resp.status_code}"}
    except requests.exceptions.Timeout:
        return {"error": "Request timed out"}
    except requests.exceptions.ConnectionError:
        return {"error": "Connection error"}
    except Exception as e:
        return {"error": str(e)}


def enrich_results(results: dict, api_key: str, verbose: bool = False) -> dict:
    """
    Enrich extracted IOCs with VirusTotal data.
    Only enriches unique IPs, domains, URIs, and hashes (first value only for hashes).
    """
    type_map = {
        "ip":     "ip",
        "dns":    "domain",
        "ssl":    "domain",
        "uri":    "url",
        "hashes": "hash",
    }

    print("\n[*] Enriching IOCs via VirusTotal (this may take a moment)...")

    for category, vt_type in type_map.items():
        if category not in results:
            continue
        seen = set()
        for entry in results[category]:
            value = entry["value"]

            # For hashes, extract the MD5 value only
            if category == "hashes":
                match = re.search(r"MD5: ([a-f0-9]{32})", value)
                if not match:
                    continue
                lookup_value = match.group(1)
            else:
                lookup_value = value

            if lookup_value in seen:
                continue
            seen.add(lookup_value)

            if verbose:
                print(f"[VT] Checking {vt_type}: {lookup_value}")

            vt_data = vt_lookup(lookup_value, vt_type, api_key, verbose)
            entry["virustotal"] = vt_data

            # Rate limit: free tier = 4 requests/min
            time.sleep(15)

    return results


# ──────────────────────────────────────────────
#  Packet Extraction
# ──────────────────────────────────────────────

def extract_data(pcap_file: str, filters: list, verbose: bool = False) -> dict:
    """Extract IOCs from a PCAP file based on the selected filters."""
    try:
        cap = pyshark.FileCapture(pcap_file, use_json=True, include_raw=True)
    except Exception as e:
        print(f"[ERROR] Failed to open PCAP: {e}")
        sys.exit(1)

    results = defaultdict(list)
    email_regex = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
    url_regex   = re.compile(r"https?://[\w.\-]+(?:/\S*)?")
    packet_count = 0

    try:
        for pkt in cap:
            packet_count += 1
            ts = datetime.fromtimestamp(float(pkt.sniff_timestamp))
            timestamp = format_timestamp(ts)

            # ── IP ──
            if "ip" in filters and hasattr(pkt, "ip"):
                results["ip"].append({"value": pkt.ip.src, "timestamp": timestamp})
                results["ip"].append({"value": pkt.ip.dst, "timestamp": timestamp})

            # ── DNS ──
            if "dns" in filters and hasattr(pkt, "dns") and hasattr(pkt.dns, "qry_name"):
                results["dns"].append({"value": pkt.dns.qry_name, "timestamp": timestamp})

            # ── SSL/TLS SNI ──
            if "ssl" in filters and hasattr(pkt, "ssl") and hasattr(pkt.ssl, "handshake_extensions_server_name"):
                results["ssl"].append({"value": pkt.ssl.handshake_extensions_server_name, "timestamp": timestamp})

            # ── FTP ──
            if "ftp" in filters and hasattr(pkt, "ftp") and hasattr(pkt.ftp, "request_command"):
                results["ftp"].append({"value": pkt.ftp.request_command, "timestamp": timestamp})

            # ── SMTP ──
            if "smtp" in filters:
                if hasattr(pkt, "smtp") and hasattr(pkt.smtp, "req_parameter"):
                    results["smtp"].append({"value": pkt.smtp.req_parameter, "timestamp": timestamp})
                if hasattr(pkt, "info"):
                    info = pkt.info.lower()
                    if "@" in info:
                        for part in info.split():
                            if "@" in part and "." in part:
                                results["smtp"].append({"value": part, "timestamp": timestamp})
                                if verbose:
                                    print(f"[VERBOSE] SMTP email in info: {part}")

            # ── HTTP ──
            if "http" in filters and hasattr(pkt, "http"):
                http = pkt.http
                # Host header
                if hasattr(http, "host"):
                    results["http"].append({
                        "value": f"HOST: {http.host}",
                        "timestamp": timestamp,
                    })
                # Request URI
                if hasattr(http, "request_uri"):
                    host = getattr(http, "host", "")
                    uri  = http.request_uri
                    full = f"http://{host}{uri}" if host else uri
                    results["http"].append({
                        "value": f"URI: {full}",
                        "timestamp": timestamp,
                    })
                # Method
                if hasattr(http, "request_method"):
                    results["http"].append({
                        "value": f"METHOD: {http.request_method}",
                        "timestamp": timestamp,
                    })
                # User-Agent
                if hasattr(http, "user_agent"):
                    results["http"].append({
                        "value": f"USER-AGENT: {http.user_agent}",
                        "timestamp": timestamp,
                    })
                    if verbose:
                        print(f"[VERBOSE] HTTP User-Agent: {http.user_agent}")
                # Response code
                if hasattr(http, "response_code"):
                    results["http"].append({
                        "value": f"RESPONSE: {http.response_code}",
                        "timestamp": timestamp,
                    })

            # ── Ports ──
            if "port" in filters and hasattr(pkt, "ip"):
                proto = src_port = dst_port = None
                if hasattr(pkt, "tcp"):
                    proto    = "TCP"
                    src_port = pkt.tcp.srcport
                    dst_port = pkt.tcp.dstport
                elif hasattr(pkt, "udp"):
                    proto    = "UDP"
                    src_port = pkt.udp.srcport
                    dst_port = pkt.udp.dstport
                if src_port:
                    results["port"].append({
                        "value":     f"[{proto}] {pkt.ip.src}:{src_port} → {pkt.ip.dst}:{dst_port}",
                        "timestamp": timestamp,
                    })

            # ── Heuristic: emails in raw packet ──
            packet_str   = str(pkt)
            found_emails = email_regex.findall(packet_str)
            for email in found_emails:
                if all(email != e["value"] for e in results["smtp"]):
                    results["smtp"].append({"value": email, "timestamp": timestamp})
                    if verbose:
                        print(f"[VERBOSE] Heuristic email: {email}")

            # ── URI heuristic ──
            if "uri" in filters:
                for url in url_regex.findall(packet_str):
                    results["uri"].append({"value": url, "timestamp": timestamp})
                    if verbose:
                        print(f"[VERBOSE] URI: {url}")

            # ── Payload hashes ──
            if "hashes" in filters and hasattr(pkt, "data") and hasattr(pkt.data, "data"):
                raw = pkt.data.data.replace(":", "")
                try:
                    byte_data = bytes.fromhex(raw)
                    md5    = hashlib.md5(byte_data).hexdigest()
                    sha1   = hashlib.sha1(byte_data).hexdigest()
                    sha256 = hashlib.sha256(byte_data).hexdigest()
                    results["hashes"].append({
                        "value":     f"MD5: {md5}, SHA1: {sha1}, SHA256: {sha256}",
                        "timestamp": timestamp,
                    })
                    if verbose:
                        print(f"[VERBOSE] Hashes => MD5:{md5}")
                except Exception as e:
                    if verbose:
                        print(f"[ERROR] Hash extraction failed: {e}")

    finally:
        cap.close()

    if not results:
        print(f"[!] No IOCs found. Processed {packet_count} packets.")
    else:
        total = sum(len(v) for v in results.values())
        print(f"[+] Processed {packet_count} packets — found {total} raw IOC entries.")

    return results


# ──────────────────────────────────────────────
#  Deduplication
# ──────────────────────────────────────────────

def deduplicate(results: dict, target: str = None) -> dict:
    """
    Remove duplicate IOC values.
    target: deduplicate only this category (e.g. 'ip'), or all if None.
    """
    deduped = defaultdict(list)
    for category, entries in results.items():
        if target is None or category == target:
            seen = set()
            for entry in entries:
                if entry["value"] not in seen:
                    deduped[category].append(entry)
                    seen.add(entry["value"])
        else:
            deduped[category] = entries
    return deduped


# ──────────────────────────────────────────────
#  Export
# ──────────────────────────────────────────────

def _vt_summary(entry: dict) -> str:
    """Return a short VT reputation string for an entry."""
    vt = entry.get("virustotal")
    if not vt:
        return ""
    if "error" in vt:
        return f"VT: {vt['error']}"
    mal = vt.get("malicious", 0)
    sus = vt.get("suspicious", 0)
    rep = vt.get("reputation", "N/A")
    return f"VT malicious={mal} suspicious={sus} reputation={rep}"


def save_csv(results: dict, filename: str) -> None:
    path = f"{filename}_report.csv"
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Category", "Timestamp", "Value", "VT_Malicious",
                         "VT_Suspicious", "VT_Reputation", "VT_Country"])
        for category, entries in results.items():
            for entry in entries:
                vt = entry.get("virustotal", {})
                writer.writerow([
                    category.upper(),
                    entry["timestamp"],
                    entry["value"],
                    vt.get("malicious", ""),
                    vt.get("suspicious", ""),
                    vt.get("reputation", ""),
                    vt.get("country", ""),
                ])
    print(f"[+] CSV saved: {path}")


def save_json(results: dict, filename: str) -> None:
    path = f"{filename}_report.json"
    with open(path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"[+] JSON saved: {path}")


def save_md(results: dict, filename: str) -> None:
    path = f"{filename}_report.md"
    with open(path, "w") as f:
        f.write(f"# IOC Extraction Report\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        for category, entries in results.items():
            f.write(f"## {category.upper()}\n\n")
            has_vt = any("virustotal" in e for e in entries)
            if has_vt:
                f.write("| Timestamp | Value | VT Malicious | VT Suspicious | VT Reputation |\n")
                f.write("|-----------|-------|-------------|--------------|---------------|\n")
                for entry in entries:
                    vt  = entry.get("virustotal", {})
                    mal = vt.get("malicious", "")
                    sus = vt.get("suspicious", "")
                    rep = vt.get("reputation", "")
                    f.write(f"| {entry['timestamp']} | {entry['value']} | {mal} | {sus} | {rep} |\n")
            else:
                f.write("| Timestamp | Value |\n|-----------|-------|\n")
                for entry in entries:
                    f.write(f"| {entry['timestamp']} | {entry['value']} |\n")
            f.write("\n")
    print(f"[+] Markdown saved: {path}")


def save_html(results: dict, filename: str) -> None:
    path = f"{filename}_report.html"
    with open(path, "w") as f:
        f.write("""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>IOC Extraction Report</title>
<style>
  body  { font-family: 'Courier New', monospace; background:#0d1117; color:#c9d1d9; margin:2rem; }
  h1    { color:#58a6ff; border-bottom:1px solid #30363d; padding-bottom:.5rem; }
  h2    { color:#79c0ff; margin-top:2rem; }
  table { width:100%; border-collapse:collapse; margin-top:.5rem; font-size:.85rem; }
  th    { background:#161b22; color:#58a6ff; border:1px solid #30363d; padding:8px 12px; text-align:left; }
  td    { border:1px solid #21262d; padding:6px 12px; word-break:break-all; }
  tr:hover td { background:#161b22; }
  .mal  { color:#f85149; font-weight:bold; }
  .sus  { color:#e3b341; }
  .ok   { color:#3fb950; }
  .ts   { color:#8b949e; font-size:.8rem; }
</style>
</head>
<body>
""")
        f.write(f"<h1>🔍 IOC Extraction Report</h1>\n")
        f.write(f"<p class='ts'>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>\n")

        for category, entries in results.items():
            f.write(f"<h2>{category.upper()} ({len(entries)} entries)</h2>\n")
            has_vt = any("virustotal" in e for e in entries)
            f.write("<table>\n")
            if has_vt:
                f.write("<tr><th>Timestamp</th><th>Value</th><th>VT Malicious</th>"
                        "<th>VT Suspicious</th><th>Reputation</th><th>Country</th></tr>\n")
            else:
                f.write("<tr><th>Timestamp</th><th>Value</th></tr>\n")

            for entry in entries:
                vt = entry.get("virustotal", {})
                mal = vt.get("malicious", "")
                sus = vt.get("suspicious", "")
                rep = vt.get("reputation", "")
                country = vt.get("country", "")

                mal_class = "mal" if isinstance(mal, int) and mal > 0 else "ok" if mal == 0 else ""
                sus_class = "sus" if isinstance(sus, int) and sus > 0 else ""

                if has_vt:
                    f.write(f"<tr>"
                            f"<td class='ts'>{entry['timestamp']}</td>"
                            f"<td>{entry['value']}</td>"
                            f"<td class='{mal_class}'>{mal}</td>"
                            f"<td class='{sus_class}'>{sus}</td>"
                            f"<td>{rep}</td>"
                            f"<td>{country}</td>"
                            f"</tr>\n")
                else:
                    f.write(f"<tr><td class='ts'>{entry['timestamp']}</td>"
                            f"<td>{entry['value']}</td></tr>\n")

            f.write("</table>\n")

        f.write("</body></html>\n")
    print(f"[+] HTML saved: {path}")


# ──────────────────────────────────────────────
#  CLI
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Extract IOCs from PCAP files with optional VirusTotal enrichment.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("pcap", help="Path to the PCAP file")

    # Filters
    filter_group = parser.add_argument_group("IOC filters")
    for flag in ["ip", "dns", "ssl", "ftp", "smtp", "http", "port", "hashes", "uri"]:
        filter_group.add_argument(f"--{flag}", action="store_true",
                                  help=f"Extract {flag.upper()} indicators")
    filter_group.add_argument("--all", action="store_true", help="Extract all IOC types")

    # Dedup
    dedup_group = parser.add_argument_group("Deduplication")
    dedup_group.add_argument("--dedup",        action="store_true", help="Deduplicate all categories")
    dedup_group.add_argument("--dedup-ip",     action="store_true", help="Deduplicate IP addresses only")
    dedup_group.add_argument("--dedup-domain", action="store_true", help="Deduplicate DNS/SSL domains only")

    # VirusTotal
    vt_group = parser.add_argument_group("VirusTotal enrichment")
    vt_group.add_argument("--vt-enrich", action="store_true",
                          help="Enrich IOCs via VirusTotal API")
    vt_group.add_argument("--vt-key", metavar="API_KEY",
                          default=os.environ.get("VT_API_KEY"),
                          help="VirusTotal API key (or set VT_API_KEY env var)")

    # Output
    out_group = parser.add_argument_group("Output formats")
    out_group.add_argument("--csv",  action="store_true")
    out_group.add_argument("--json", action="store_true")
    out_group.add_argument("--md",   action="store_true")
    out_group.add_argument("--html", action="store_true")

    # Misc
    parser.add_argument("--quiet",   action="store_true", help="Suppress console output")
    parser.add_argument("--verbose", action="store_true", help="Show detailed processing info")

    args = parser.parse_args()

    # Validate input file
    validate_pcap(args.pcap)

    # Build filter list
    all_filters = ["ip", "dns", "ssl", "ftp", "smtp", "http", "port", "hashes", "uri"]
    filters = all_filters if args.all else [f for f in all_filters if getattr(args, f, False)]

    if not filters:
        print("[!] No filters selected. Use --all or specify at least one filter (e.g. --ip --dns).")
        parser.print_help()
        sys.exit(1)

    # Extract
    results = extract_data(args.pcap, filters, verbose=args.verbose)

    # Deduplicate
    if args.dedup:
        results = deduplicate(results)
    elif args.dedup_ip:
        results = deduplicate(results, target="ip")
    elif args.dedup_domain:
        results = deduplicate(results, target="dns")

    # VirusTotal enrichment
    if args.vt_enrich:
        if not args.vt_key:
            print("[ERROR] VirusTotal enrichment requested but no API key provided.")
            print("        Use --vt-key YOUR_KEY or set the VT_API_KEY environment variable.")
            sys.exit(1)
        results = enrich_results(results, args.vt_key, verbose=args.verbose)

    # Save outputs
    filename = os.path.splitext(args.pcap)[0]
    if args.csv:  save_csv(results, filename)
    if args.json: save_json(results, filename)
    if args.md:   save_md(results, filename)
    if args.html: save_html(results, filename)

    # Console output
    if not args.quiet:
        for category, entries in results.items():
            print(f"\n{'═'*50}")
            print(f"  {category.upper()} ({len(entries)} entries)")
            print(f"{'═'*50}")
            for entry in entries:
                vt_str = _vt_summary(entry)
                vt_str = f"  [{vt_str}]" if vt_str else ""
                print(f"  [{entry['timestamp']}] {entry['value']}{vt_str}")

        print("\n[✓] Extraction complete.")


if __name__ == "__main__":
    main()
