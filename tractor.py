#!/usr/bin/env python3
import pyshark
import argparse
import csv
import json
import re
import hashlib
from datetime import datetime
from collections import defaultdict
import os

def format_timestamp(ts):
    return ts.strftime("%d/%m/%Y %I:%M:%S %p")

def extract_data(pcap_file, filters, verbose=False):
    cap = pyshark.FileCapture(pcap_file, use_json=True, include_raw=True)
    results = defaultdict(list)
    email_regex = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
    url_regex = re.compile(r"https?://[\w\.-]+(?:/\S*)?")
    try:
        for pkt in cap:
            ts = datetime.fromtimestamp(float(pkt.sniff_timestamp))
            timestamp = format_timestamp(ts)
            if 'ip' in filters and hasattr(pkt, 'ip'):
                results['ip'].append({'value': pkt.ip.src, 'timestamp': timestamp})
                results['ip'].append({'value': pkt.ip.dst, 'timestamp': timestamp})
            if 'dns' in filters and hasattr(pkt, 'dns') and hasattr(pkt.dns, 'qry_name'):
                results['dns'].append({'value': pkt.dns.qry_name, 'timestamp': timestamp})
            if 'ssl' in filters and hasattr(pkt, 'ssl') and hasattr(pkt.ssl, 'handshake_extensions_server_name'):
                results['ssl'].append({'value': pkt.ssl.handshake_extensions_server_name, 'timestamp': timestamp})
            if 'ftp' in filters and hasattr(pkt, 'ftp') and hasattr(pkt.ftp, 'request_command'):
                results['ftp'].append({'value': pkt.ftp.request_command, 'timestamp': timestamp})
            if 'smtp' in filters:
                if hasattr(pkt, 'smtp') and hasattr(pkt.smtp, 'req_parameter'):
                    results['smtp'].append({'value': pkt.smtp.req_parameter, 'timestamp': timestamp})
                if hasattr(pkt, 'info'):
                    info = pkt.info.lower()
                    if '@' in info:
                        for part in info.split():
                            if '@' in part and '.' in part:
                                results['smtp'].append({'value': part, 'timestamp': timestamp})
                                if verbose:
                                    print(f"[VERBOSE] Found SMTP email in info: {part}")
            if 'port' in filters and hasattr(pkt, 'ip'):
                proto = None
                src_port = dst_port = None
                if hasattr(pkt, 'tcp'):
                    proto = 'TCP'
                    src_port = pkt.tcp.srcport
                    dst_port = pkt.tcp.dstport
                elif hasattr(pkt, 'udp'):
                    proto = 'UDP'
                    src_port = pkt.udp.srcport
                    dst_port = pkt.udp.dstport
                if src_port:
                    results['port'].append({'value': f"{pkt.ip.src}:{src_port} → {pkt.ip.dst}", 'timestamp': timestamp})
                if dst_port:
                    results['port'].append({'value': f"{pkt.ip.dst}:{dst_port} ← {pkt.ip.src}", 'timestamp': timestamp})

            packet_str = str(pkt)
            found_emails = email_regex.findall(packet_str)
            for email in found_emails:
                if all(email != entry['value'] for entry in results['smtp']):
                    results['smtp'].append({'value': email, 'timestamp': timestamp})
                    if verbose:
                        print(f"[VERBOSE] Heuristic email found: {email}")

            if 'uri' in filters:
                found_urls = url_regex.findall(packet_str)
                for url in found_urls:
                    results['uri'].append({'value': url, 'timestamp': timestamp})
                    if verbose:
                        print(f"[VERBOSE] Found URI: {url}")

            if 'hashes' in filters and hasattr(pkt, 'data') and hasattr(pkt.data, 'data'):
                raw_data = pkt.data.data.replace(':', '')
                try:
                    byte_data = bytes.fromhex(raw_data)
                    md5 = hashlib.md5(byte_data).hexdigest()
                    sha1 = hashlib.sha1(byte_data).hexdigest()
                    sha256 = hashlib.sha256(byte_data).hexdigest()
                    results['hashes'].append({'value': f"MD5: {md5}, SHA1: {sha1}, SHA256: {sha256}", 'timestamp': timestamp})
                    if verbose:
                        print(f"[VERBOSE] Extracted Hashes => MD5: {md5}, SHA1: {sha1}, SHA256: {sha256}")
                except Exception as e:
                    if verbose:
                        print(f"[ERROR] Failed to parse data for hashing: {e}")
    finally:
        cap.close()
    return results

def deduplicate(results, mode=None):
    deduped = defaultdict(list)
    for k, v in results.items():
        seen = set()
        for entry in v:
            if (mode and k == mode) or not mode:
                if entry['value'] not in seen:
                    deduped[k].append(entry)
                    seen.add(entry['value'])
            else:
                deduped[k].append(entry)
    return deduped

def save_csv(results, filename):
    combined_filename = f'{filename}_report.csv'
    with open(combined_filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Category', 'Timestamp', 'Value'])
        for key, values in results.items():
            for entry in values:
                writer.writerow([key.upper(), entry['timestamp'], entry['value']])

def save_json(results, filename):
    with open(f"{filename}_report.json", "w") as f:
        json.dump(results, f, indent=2)

def save_md(results, filename):
    with open(f"{filename}_report.md", "w") as f:
        for k, v in results.items():
            f.write(f"### {k.upper()}\n")
            f.write("| Timestamp | Value |\n|-----------|-------|\n")
            for entry in v:
                f.write(f"| {entry['timestamp']} | {entry['value']} |\n")
            f.write("\n")

def save_html(results, filename):
    with open(f"{filename}_report.html", "w") as f:
        f.write("<html><head><style>")
        f.write("body { font-family: Arial; }")
        f.write("table { width: 100%; border-collapse: collapse; }")
        f.write("th, td { border: 1px solid #ccc; padding: 8px; }")
        f.write("th { background-color: #cce5ff; }")
        f.write("</style></head><body>")
        for k, v in results.items():
            f.write(f"<h2>{k.upper()}</h2>")
            f.write("<table><tr><th>Timestamp</th><th>Value</th></tr>")
            for entry in v:
                f.write(f"<tr><td>{entry['timestamp']}</td><td>{entry['value']}</td></tr>")
            f.write("</table><br>")
        f.write("</body></html>")

def main():
    parser = argparse.ArgumentParser(description="Extract IOCs from PCAP files.")
    parser.add_argument("pcap", help="PCAP file to analyze")
    parser.add_argument("--ip", action="store_true")
    parser.add_argument("--dns", action="store_true")
    parser.add_argument("--ssl", action="store_true")
    parser.add_argument("--ftp", action="store_true")
    parser.add_argument("--smtp", action="store_true")
    parser.add_argument("--port", action="store_true")
    parser.add_argument("--hashes", action="store_true")
    parser.add_argument("--uri", action="store_true")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--dedup", action="store_true")
    parser.add_argument("--dedup-ip", action="store_true")
    parser.add_argument("--dedup-domain", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--csv", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--md", action="store_true")
    parser.add_argument("--html", action="store_true")
    args = parser.parse_args()

    filters = []
    if args.all:
        filters = ["ip", "dns", "ssl", "ftp", "smtp", "port", "hashes", "uri"]
    else:
        for attr in ["ip", "dns", "ssl", "ftp", "smtp", "port", "hashes", "uri"]:
            if getattr(args, attr):
                filters.append(attr)

    results = extract_data(args.pcap, filters, verbose=args.verbose)

    if args.dedup or args.dedup_ip:
        results = deduplicate(results, "ip" if args.dedup_ip else None)

    filename = os.path.splitext(args.pcap)[0]

    if args.csv:
        save_csv(results, filename)
    if args.json:
        save_json(results, filename)
    if args.md:
        save_md(results, filename)
    if args.html:
        save_html(results, filename)

    if not args.quiet:
        for k, v in results.items():
            print(f"\n=== {k.upper()} ===")
            for entry in v:
                print(f"[{entry['timestamp']}] {entry['value']}")
        print("\nExtraction is complete. You may bask in your glorious report collection now.")

if __name__ == "__main__":
    main()
