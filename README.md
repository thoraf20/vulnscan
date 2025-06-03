# GoVulnScan

VulnScan is a Go-based CLI tool for network and web vulnerability scanning. It performs concurrent TCP port scanning with service detection, checks web headers, probes for XSS/SQL injection vulnerabilities, and queries the NVD API for CVEs.

## Features
- **Concurrent TCP port scanning with service detection (e.g., SSH, HTTP).
- **Web Scanning**: Web scanning for insecure headers and XSS/SQLi vulnerabilities.
- **CVE Scanning**: Queries the NVD API for CVEs.
- **Output Formats**: Supports table and JSON output (`--format`) and file saving (`--output` for JSON/CSV).
- **Customizable**: Allows for customizing the scanning process with flags and configuration files.
- **Mocked tests for reliability.
- **Logging**: Structured logging with `logrus` for debugging and results.

## Installation
```bash
go install github.com/thoraf20/vulnscan/cmd/vulnscan@latest

# git clone https://github.com/thoraf20/vulnscan.git
# cd vulnscan
# go build -o vulnscan ./cmd/vulnscan
```
## Usage
# vulnscan scan --target scanme.nmap.org --type network --ports 20-25,80,443 --format yaml --output network.yaml
# vulnscan scan --target example.com --type web --format json --output web.json
# Network scan with table output
# vulnscan scan --target scanme.nmap.org --type network --ports 20-

## Flags
- --type (-y): Scan type (network or web, default: network)
- --ports (-p): Ports to scan (e.g., 22,80,443, default: 22,80,443)
- --format (-f): Output format (table or json, default: table)
- --output (-o): Output file (.json or .csv, default: none)

## Development
- git clone https://github.com/thoraf20/vulnscan
- cd vulnscan
- go build -o vulnscan.exe ./cmd/vulnscan
- go test ./...


## License
### MIT License
