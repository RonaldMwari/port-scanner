#!/usr/bin/env python3
"""
Network Port Scanner
--------------------
A multithreaded TCP port scanner with banner grabbing and report export.
Author: [Your Name]
"""

import socket
import threading
import argparse
import json
import sys
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─────────────────────────────────────────────
# Common service names by port number
# ─────────────────────────────────────────────
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB"
}

# Thread-safe lock for printing
print_lock = threading.Lock()


def resolve_host(target: str) -> str:
    """Resolve hostname to IP address."""
    try:
        ip = socket.gethostbyname(target)
        return ip
    except socket.gaierror:
        print(f"[ERROR] Could not resolve host: {target}")
        sys.exit(1)


def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    """
    Attempt to grab a service banner from an open port.
    Sends a generic HTTP request to HTTP-like ports, otherwise just reads.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            # Send a probe for HTTP ports
            if port in (80, 8080, 8443, 443):
                s.send(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
            else:
                s.send(b"\r\n")
            banner = s.recv(1024).decode(errors="ignore").strip()
            # Return just the first line of the banner
            return banner.splitlines()[0] if banner else ""
    except Exception:
        return ""


def scan_port(ip: str, port: int, timeout: float, grab_banners: bool) -> dict | None:
    """
    Attempt a TCP connection to a single port.
    Returns a result dict if port is open, None if closed/filtered.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            if result == 0:
                service = COMMON_PORTS.get(port, "Unknown")
                banner = grab_banner(ip, port, timeout) if grab_banners else ""
                return {
                    "port": port,
                    "state": "open",
                    "service": service,
                    "banner": banner
                }
    except socket.error:
        pass
    return None


def run_scan(target: str, port_range: tuple, timeout: float,
             threads: int, grab_banners: bool) -> list:
    """
    Run a multithreaded port scan over the given range.
    Returns a list of open port results.
    """
    ip = resolve_host(target)
    start_port, end_port = port_range
    total_ports = end_port - start_port + 1
    open_ports = []
    scanned = 0

    print(f"\n{'='*55}")
    print(f"  Target    : {target} ({ip})")
    print(f"  Port Range: {start_port} - {end_port}  ({total_ports} ports)")
    print(f"  Threads   : {threads}")
    print(f"  Timeout   : {timeout}s per port")
    print(f"  Banners   : {'Yes' if grab_banners else 'No'}")
    print(f"  Started   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*55}\n")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(scan_port, ip, port, timeout, grab_banners): port
            for port in range(start_port, end_port + 1)
        }

        for future in as_completed(futures):
            scanned += 1
            result = future.result()
            if result:
                open_ports.append(result)
                with print_lock:
                    banner_info = f"  │  {result['banner']}" if result["banner"] else ""
                    print(f"  [OPEN]  Port {result['port']:>5}  │  {result['service']:<14}{banner_info}")

            # Progress indicator every 100 ports
            if scanned % 100 == 0:
                with print_lock:
                    pct = (scanned / total_ports) * 100
                    print(f"  ... {scanned}/{total_ports} ports scanned ({pct:.0f}%)", end="\r")

    # Sort results by port number
    open_ports.sort(key=lambda x: x["port"])
    return ip, open_ports


def export_report(target: str, ip: str, open_ports: list, fmt: str, output_file: str):
    """Export scan results to a text or JSON file."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if fmt == "json":
        report = {
            "scan_time": timestamp,
            "target": target,
            "ip": ip,
            "open_ports": open_ports
        }
        with open(output_file, "w") as f:
            json.dump(report, f, indent=2)

    else:  # plain text
        with open(output_file, "w") as f:
            f.write(f"Port Scan Report\n")
            f.write(f"{'='*55}\n")
            f.write(f"Target    : {target} ({ip})\n")
            f.write(f"Scan Time : {timestamp}\n")
            f.write(f"Open Ports: {len(open_ports)}\n")
            f.write(f"{'='*55}\n\n")
            if open_ports:
                f.write(f"{'PORT':<8}{'STATE':<10}{'SERVICE':<16}{'BANNER'}\n")
                f.write(f"{'-'*55}\n")
                for p in open_ports:
                    f.write(f"{p['port']:<8}{'open':<10}{p['service']:<16}{p['banner']}\n")
            else:
                f.write("No open ports found.\n")

    print(f"\n  [+] Report saved to: {output_file}")


def parse_args():
    parser = argparse.ArgumentParser(
        description="🔍 Network Port Scanner — TCP multithreaded scanner with banner grabbing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python port_scanner.py scanme.nmap.org
  python port_scanner.py 192.168.1.1 -p 1-1024
  python port_scanner.py example.com -p 80,443,8080 -b -o report.txt
  python port_scanner.py 10.0.0.1 -p 1-65535 -t 200 --format json -o results.json
        """
    )
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument(
        "-p", "--ports", default="1-1024",
        help="Port range (e.g. 1-1024) or comma-separated list (e.g. 22,80,443). Default: 1-1024"
    )
    parser.add_argument("-t", "--threads", type=int, default=100,
                        help="Number of threads (default: 100)")
    parser.add_argument("--timeout", type=float, default=1.0,
                        help="Connection timeout in seconds (default: 1.0)")
    parser.add_argument("-b", "--banners", action="store_true",
                        help="Attempt to grab service banners from open ports")
    parser.add_argument("-o", "--output", default=None,
                        help="Output file for the report (e.g. report.txt or results.json)")
    parser.add_argument("--format", choices=["txt", "json"], default="txt",
                        help="Report format: txt or json (default: txt)")
    return parser.parse_args()


def parse_ports(port_str: str) -> tuple:
    """Parse port input into a (start, end) tuple."""
    if "-" in port_str:
        parts = port_str.split("-")
        return int(parts[0]), int(parts[1])
    elif "," in port_str:
        ports = [int(p) for p in port_str.split(",")]
        return min(ports), max(ports)
    else:
        p = int(port_str)
        return p, p


def main():
    args = parse_args()

    try:
        port_range = parse_ports(args.ports)
    except ValueError:
        print("[ERROR] Invalid port format. Use: 1-1024 or 80,443,8080")
        sys.exit(1)

    if port_range[0] < 1 or port_range[1] > 65535:
        print("[ERROR] Ports must be between 1 and 65535.")
        sys.exit(1)

    start_time = datetime.now()
    ip, open_ports = run_scan(
        target=args.target,
        port_range=port_range,
        timeout=args.timeout,
        threads=args.threads,
        grab_banners=args.banners
    )
    elapsed = (datetime.now() - start_time).total_seconds()

    print(f"\n{'='*55}")
    print(f"  Scan complete in {elapsed:.2f}s")
    print(f"  Open ports found: {len(open_ports)}")
    print(f"{'='*55}")

    if args.output:
        export_report(args.target, ip, open_ports, args.format, args.output)


if __name__ == "__main__":
    main()