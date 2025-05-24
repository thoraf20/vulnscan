package cmd

import (
    "github.com/spf13/cobra"
    "github.com/thoraf20/vulnscan/internal/config"
    "github.com/thoraf20/vulnscan/pkg/scanner"
    "github.com/thoraf20/vulnscan/pkg/cve"
    "strconv"
    "strings"
)

var log = config.InitLogger()

var scanCmd = &cobra.Command{
    Use:   "scan",
    Short: "Scan a target for vulnerabilities",
    Run: func(cmd *cobra.Command, args []string) {
        target, _ := cmd.Flags().GetString("target")
        if target == "" {
            log.Error("Error: --target is required")
            cmd.Usage()
            return
        }
        scanType, err := cmd.Flags().GetString("type")
        if err != nil || (scanType != "network" && scanType != "web") {
            log.Error("Invalid scan type. Use 'network' or 'web'")
            cmd.Usage()
            return
        }
        if scanType == "network" {
            log.Infof("Starting network scan on %s...", target)
            portsStr, err := cmd.Flags().GetString("ports")
            if err != nil {
                log.Error("Invalid ports format")
                cmd.Usage()
                return
            }
            var ports []int
            for _, p := range strings.Split(portsStr, ",") {
                port, err := strconv.Atoi(strings.TrimSpace(p))
                if err != nil || port < 1 || port > 65535 {
                    log.Error("Invalid port range")
                    cmd.Usage()
                    return
                }
                ports = append(ports, port)
            }
            results := scanner.ScanTCPPorts(target, ports)
            for _, result := range results {
                if result.Open {
                    log.Infof("Port %d is open on %s", result.Port, target)
                    cveResults := cve.LookupCVE(result.Port)
                    for _, cveResult := range cveResults {
                        if cveResult.Error == nil && cveResult.CVEID != "" {
                            log.Infof("CVE: %s - %s", cveResult.CVEID, cveResult.Description)
                        }
                    }
                } else {
                    log.Warnf("Port %d is closed or filtered on %s", result.Port, target)
                }
            }
        } else {
          log.Infof("Starting web scan on %s...", target)
          result := scanner.ScanWeb(target)
          if result.Error == nil {
              log.Infof("Web scan result for %s: %s", result.URL, result.Status)
              for k, v := range result.Headers {
                log.Infof("Header: %s: %s", k, v)
              }
              for _, vuln := range result.Vulnerabilities {
                log.Warnf("Vulnerability: %s", vuln)
             }
          } else {
              log.Warnf("Web scan failed: %v", result.Error)
          }
      }
    },
}

func init() {
    rootCmd.AddCommand(scanCmd)
    scanCmd.Flags().StringP("type", "y", "network", "Scan type (network, web)")
    scanCmd.Flags().StringP("ports", "p", "22,80,443", "Ports to scan (e.g., 22,80,443)")
}