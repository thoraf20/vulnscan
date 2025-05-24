package cmd

import (
    "encoding/json"
    "github.com/gocarina/gocsv"
    "github.com/olekukonko/tablewriter"
    "github.com/spf13/cobra"
    "github.com/thoraf20/vulnscan/internal/config"
    "github.com/thoraf20/vulnscan/pkg/cve"
    "github.com/thoraf20/vulnscan/pkg/scanner"
    "os"
    "path/filepath"
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
        outputFile, err := cmd.Flags().GetString("output")
        if err != nil {
            log.Error("Invalid output file")
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
                Port    int    `csv:"Port"`
                Status  string `csv:"Status"`
                Service string `csv:"Service"`
                CVEs    string `csv:"CVEs"`
            }
            var output []networkOutput
            for _, result := range results {
                cveStr := ""
                if result.Open {
                    cveResults := cve.LookupCVE(result.Service)
                    for _, c := range cveResults {
                        if c.CVEID != "" {
                            cveStr += c.CVEID + "; "
                        }
                    }
                    cveStr = strings.TrimSuffix(cveStr, "; ")
                }
                output = append(output, networkOutput{
                    Port:    result.Port,
                    Status:  map[bool]string{true: "open", false: "closed"}[result.Open],
                    Service: result.Service,
                    CVEs:    cveStr,
                })
            }
            if outputFile != "" {
                ext := strings.ToLower(filepath.Ext(outputFile))
                if ext == ".json" {
                    jsonData, _ := json.MarshalIndent(output, "", "  ")
                    if err := os.WriteFile(outputFile, jsonData, 0644); err != nil {
                        log.Errorf("Failed to write JSON file: %v", err)
                        return
                    }
                    log.Infof("Results saved to %s", outputFile)
                } else if ext == ".csv" {
                    file, err := os.Create(outputFile)
                    if err != nil {
                        log.Errorf("Failed to create CSV file: %v", err)
                        return
                    }
                    defer file.Close()
                    if err := gocsv.MarshalFile(&output, file); err != nil {
                        log.Errorf("Failed to write CSV file: %v", err)
                        return
                    }
                    log.Infof("Results saved to %s", outputFile)
                } else {
                    log.Error("Output file must be .json or .csv")
                    return
                }
            }
            if format == "json" {
                jsonData, _ := json.MarshalIndent(output, "", "  ")
                os.Stdout.Write(jsonData)
            } else {
                table := tablewriter.NewWriter(os.Stdout)
                table.Header([]string{"Port", "Status", "Service", "CVEs"})
                for _, item := range output {
                    table.Append([]string{
                        strconv.Itoa(item.Port),
                        item.Status,
                        item.Service,
                        item.CVEs,
                    })
                }
                table.Render()
            }
        } else {
            log.Infof("Starting web scan on %s...", target)
            result := scanner.ScanWeb(target)
            type webOutput struct {
                URL          string `csv:"URL"`
                Status       string `csv:"Status"`
                Headers      string `csv:"Headers"`
                Vulnerabilities string `csv:"Vulnerabilities"`
            }
            headersStr := ""
            for k, v := range result.Headers {
                headersStr += k + ": " + v + "; "
            }
            headersStr = strings.TrimSuffix(headersStr, "; ")
            output := webOutput{
                URL:          result.URL,
                Status:       result.Status,
                Headers:      headersStr,
                Vulnerabilities: strings.Join(result.Vulnerabilities, "; "),
            }
            if outputFile != "" {
                ext := strings.ToLower(filepath.Ext(outputFile))
                if ext == ".json" {
                    jsonData, _ := json.MarshalIndent(output, "", "  ")
                    if err := os.WriteFile(outputFile, jsonData, 0644); err != nil {
                        log.Errorf("Failed to write JSON file: %v", err)
                        return
                    }
                    log.Infof("Results saved to %s", outputFile)
                } else if ext == ".csv" {
                    file, err := os.Create(outputFile)
                    if err != nil {
                        log.Errorf("Failed to create CSV file: %v", err)
                        return
                    }
                    defer file.Close()
                    outputs := []webOutput{output}
                    if err := gocsv.MarshalFile(&outputs, file); err != nil {
                        log.Errorf("Failed to write CSV file: %v", err)
                        return
                    }
                    log.Infof("Results saved to %s", outputFile)
                } else {
                    log.Error("Output file must be .json or .csv")
                    return
                }
            }
            if format == "json" {
                jsonData, _ := json.MarshalIndent(output, "", "  ")
                os.Stdout.Write(jsonData)
            } else {
                table := tablewriter.NewWriter(os.Stdout)
                table.Header([]string{"URL", "Status", "Vulnerabilities"})
                table.Append([]string{result.URL, result.Status, strings.Join(result.Vulnerabilities, "; ")})
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
    scanCmd.Flags().StringP("output", "o", "", "Output file (e.g., results.json or results.csv)")
}