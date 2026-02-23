# 🔍 Network Port Scanner

A multithreaded TCP port scanner written in Python. Designed to identify open ports on a target host, detect running services, grab service banners, and export results to a structured report.

> ⚠️ **Ethical Use Only** — Only scan systems you own or have explicit written permission to test. Unauthorized scanning may be illegal.

---

## Features

- **Multithreaded scanning** — Uses a configurable thread pool for fast scans
- **Banner grabbing** — Identifies service versions on open ports
- **Service detection** — Maps common ports to service names (SSH, HTTP, FTP, etc.)
- **Flexible port input** — Supports ranges (`1-1024`) or lists (`22,80,443`)
- **Report export** — Save results as `.txt` or `.json`
- **Progress indicator** — Shows live progress during large scans

---

## Requirements

- Python 3.10+
- No external libraries required (uses stdlib only: `socket`, `threading`, `argparse`, `json`)

---

## Usage

```bash
# Basic scan (ports 1-1024)
python port_scanner.py scanme.nmap.org

# Custom port range
python port_scanner.py 192.168.1.1 -p 1-500

# Specific ports with banner grabbing
python port_scanner.py example.com -p 22,80,443 -b

# Full scan with JSON report
python port_scanner.py 10.0.0.1 -p 1-65535 -t 200 --format json -o results.json
```

### Arguments

| Flag | Description | Default |
|------|-------------|---------|
| `target` | IP address or hostname to scan | *(required)* |
| `-p`, `--ports` | Port range or comma-separated list | `1-1024` |
| `-t`, `--threads` | Number of concurrent threads | `100` |
| `--timeout` | Connection timeout (seconds) | `1.0` |
| `-b`, `--banners` | Enable banner grabbing | Off |
| `-o`, `--output` | Output file path | None |
| `--format` | Report format: `txt` or `json` | `txt` |

---

## Example Output

```
=======================================================
  Target    : scanme.nmap.org (45.33.32.156)
  Port Range: 1 - 1024  (1024 ports)
  Threads   : 100
  Timeout   : 1.0s per port
  Started   : 2025-01-15 14:32:01
=======================================================

  [OPEN]  Port    22  │  SSH             SSH-2.0-OpenSSH_6.6.1p1
  [OPEN]  Port    80  │  HTTP            HTTP/1.1 200 OK

=======================================================
  Scan complete in 4.82s
  Open ports found: 2
=======================================================
```

---

## How It Works

1. **Host Resolution** — Converts hostname to IP via `socket.gethostbyname()`
2. **TCP Connect Scan** — Attempts a full TCP handshake on each port using `connect_ex()`
3. **Banner Grabbing** — On open ports, sends a probe and reads the first response line
4. **Threading** — Uses `ThreadPoolExecutor` to scan multiple ports simultaneously
5. **Reporting** — Aggregates results and optionally writes to file

---

## Concepts Demonstrated

- TCP/IP socket programming
- Multithreading with `concurrent.futures`
- Network reconnaissance fundamentals
- CLI tool design with `argparse`
- Structured data export (JSON)

---

## Possible Extensions

- [ ] UDP port scanning
- [ ] OS fingerprinting
- [ ] CVE lookup for detected services
- [ ] HTML report output
- [ ] Ping sweep / host discovery mode
- [ ] Nmap XML output format compatibility
