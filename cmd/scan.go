package cmd

import (
    "encoding/json"
    "github.com/olekukonko/tablewriter"
    "github.com/spf13/cobra"
    "github.com/thoraf20/vulnscan/internal/config"
    "github.com/thoraf20/vulnscan/pkg/cve"
    "github.com/thoraf20/vulnscan/pkg/scanner"
    "os"
    "strconv"
    "strings"
)

var log = config.InitLogger()

var scanCmd = &cobra.Command{
    Use:   "scan",
    Short: "Scan a target for vulnerabilities",
    Run: func(cmd *cobra.Command, args []string) {
        target, err := cmd.Flags().GetString("target")
        if err != nil || target == "" {
            log.Error("Target is required")
            cmd.Usage()
            return
        }
        scanType, err := cmd.Flags().GetString("type")
        if err != nil || (scanType != "network" && scanType != "web") {
            log.Error("Invalid scan type. Use 'network' or 'web'")
            cmd.Usage()
            return
        }
        format, err := cmd.Flags().GetString("format")
        if err != nil || (format != "table" && format != "json") {
            log.Error("Invalid format. Use 'table' or 'json'")
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
            type networkOutput struct {
                Port         int
                Status       string
                CVEs         []cve.CVEResult
            }
            var output []networkOutput
            for _, result := range results {
                status := "closed"
                if result.Open {
                    status = "open"
                }
                cveResults := cve.LookupCVE(result.Port)
                output = append(output, networkOutput{
                    Port:   result.Port,
                    Status: status,
                    CVEs:   cveResults,
                })
            }
            if format == "json" {
                jsonData, _ := json.MarshalIndent(output, "", "  ")
                os.Stdout.Write(jsonData)
            } else {
                table := tablewriter.NewWriter(os.Stdout)
                table.Header([]string{"Port", "Status", "CVEs"})
                for _, item := range output {
                    cveStr := ""
                    for _, c := range item.CVEs {
                        if c.CVEID != "" {
                            cveStr += c.CVEID + "; "
                        }
                    }
                    table.Append([]string{
                        strconv.Itoa(item.Port),
                        item.Status,
                        strings.TrimSuffix(cveStr, "; "),
                    })
                }
                table.Render()
            }
        } else {
            log.Infof("Starting web scan on %s...", target)
            result := scanner.ScanWeb(target)
            type webOutput struct {
                URL          string
                Status       string
                Headers      map[string]string
                Vulnerabilities []string
            }
            output := webOutput{
                URL:          result.URL,
                Status:       result.Status,
                Headers:      result.Headers,
                Vulnerabilities: result.Vulnerabilities,
            }
            if format == "json" {
                jsonData, _ := json.MarshalIndent(output, "", "  ")
                os.Stdout.Write(jsonData)
            } else {
                table := tablewriter.NewWriter(os.Stdout)
                // table.SetHeader(true)
                table.Append([]string{"URL", "Status", "Vulnerabilities"})
                vulnStr := strings.Join(result.Vulnerabilities, "; ")
                table.Append([]string{result.URL, result.Status, vulnStr})
                table.Render()
                if len(result.Headers) > 0 {
                    log.Info("Headers:")
                    headerTable := tablewriter.NewWriter(os.Stdout)
                    headerTable.Header([]string{"Header", "Value"})
                    for k, v := range result.Headers {
                        headerTable.Append([]string{k, v})
                    }
                    headerTable.Render()
                }
            }
        }
    },
}

func init() {
    rootCmd.AddCommand(scanCmd)
    scanCmd.Flags().StringP("type", "y", "network", "Scan type (network, web)")
    scanCmd.Flags().StringP("ports", "p", "22,80,443", "Ports to scan (e.g., 22,80,443)")
    scanCmd.Flags().StringP("format", "f", "table", "Output format (table, json)")
}

// package cmd

// import (
//     "github.com/olekukonko/tablewriter"
//     "github.com/spf13/cobra"
//     "os"
// )

// var scanCmd = &cobra.Command{
//     Use:   "scan",
//     Short: "Test tablewriter",
//     Run: func(cmd *cobra.Command, args []string) {
//         table := tablewriter.NewWriter(os.Stdout)
//         table.SetHeader([]string{"Test", "Value"})
//         table.Append([]string{"Example", "OK"})
//         table.Render()
//     },
// }

// func init() {
//     rootCmd.AddCommand(scanCmd)
// }