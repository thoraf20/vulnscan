# GoVulnScan

A Go-based CLI tool for network and web vulnerability scanning.

## Features
- **Network Scanning**: Scans TCP ports (e.g., 22, 80, 443) concurrently and retrieves CVEs for open ports using the NVD API.
- **Web Scanning**: Checks HTTP status, headers, and identifies insecure headers (e.g., missing HSTSX-Frame-Options).
- **Output Formats**: Supports table and JSON output (`--format`) and file saving (`--output` for JSON/CSV).
- **Logging**: Structured logging with `logrus` for debugging and results.

## Installation
```bash
git clone https://github.com/thoraf20/vulnscan.git
cd vulnscan
go build -o vulnscan ./cmd/vulnscan
```
## Usage
# Network scan with table output
./vulnscan scan --target scanme.nmap.org --type network --ports 22,80,443 --format table

# Web scan with JSON output, save to file
./vulnscan scan --target example.com --type web --format json --output results.json

Flags
--type (-y): Scan type (network or web, default: network)
--ports (-p): Ports to scan (e.g., 22,80,443, default: 22,80,443)
--format (-f): Output format (table or json, default: table)
--output (-o): Output file (.json or .csv, default: none)

## Development
- Dependencies: cobra, logrus, tablewriter, gocsv.
- Tests: Run go test ./pkg/scanner -v and go test ./pkg/cve -v.
- Docs: See docs/learning.md for weekly progress.

## License
### MIT License
