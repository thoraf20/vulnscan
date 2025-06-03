package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gocarina/gocsv"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
	"github.com/thoraf20/vulnscan/internal/config"
	"github.com/thoraf20/vulnscan/pkg/cve"
	"github.com/thoraf20/vulnscan/pkg/scanner"
	"gopkg.in/yaml.v3"
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
		if err != nil || (format != "table" && format != "json" && format != "yaml") {
			log.Error("Invalid format. Use 'table', 'json', or 'yaml'")
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
			ports, err := parsePorts(portsStr)
			if err != nil {
				log.Errorf("Invalid port range: %v", err)
				cmd.Usage()
				return
			}
			results := scanner.ScanTCPPorts(target, ports)
			type networkOutput struct {
				Port    int    `csv:"Port" yaml:"port"`
				Status  string `csv:"Status" yaml:"status"`
				Service string `csv:"Service" yaml:"service"`
				CVEs    string `csv:"CVEs" yaml:"cves"`
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
				} else if ext == ".yaml" || ext == ".yml" {
					yamlData, _ := yaml.Marshal(output)
					if err := os.WriteFile(outputFile, yamlData, 0644); err != nil {
						log.Errorf("Failed to write YAML file: %v", err)
						return
					}
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
				} else {
					log.Error("Output file must be .json, .yaml, .yml, or .csv")
					return
				}
				log.Infof("Results saved to %s", outputFile)
			}
			if format == "json" {
				jsonData, _ := json.MarshalIndent(output, "", "  ")
				os.Stdout.Write(jsonData)
			} else if format == "yaml" {
				yamlData, _ := yaml.Marshal(output)
				os.Stdout.Write(yamlData)
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
				URL             string `csv:"URL" yaml:"url"`
				Status          string `csv:"Status" yaml:"status"`
				Headers         string `csv:"Headers" yaml:"headers"`
				Vulnerabilities string `csv:"Vulnerabilities" yaml:"vulnerabilities"`
			}
			headersStr := ""
			for k, v := range result.Headers {
				headersStr += k + ": " + v + "; "
			}
			headersStr = strings.TrimSuffix(headersStr, "; ")
			output := webOutput{
				URL:             result.URL,
				Status:          result.Status,
				Headers:         headersStr,
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
				} else if ext == ".yaml" || ext == ".yml" {
					yamlData, _ := yaml.Marshal(output)
					if err := os.WriteFile(outputFile, yamlData, 0644); err != nil {
						log.Errorf("Failed to write YAML file: %v", err)
						return
					}
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
				} else {
					log.Error("Output file must be .json, .yaml, .yml, or .csv")
					return
				}
				log.Infof("Results saved to %s", outputFile)
			}
			if format == "json" {
				jsonData, _ := json.MarshalIndent(output, "", "  ")
				os.Stdout.Write(jsonData)
			} else if format == "yaml" {
				yamlData, _ := yaml.Marshal(output)
				os.Stdout.Write(yamlData)
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

func parsePorts(portsStr string) ([]int, error) {
	var ports []int
	seen := make(map[int]bool)
	parts := strings.Split(portsStr, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid port range format: %s", part)
			}
			start, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid start port: %s", rangeParts[0])
			}
			end, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid end port: %s", rangeParts[1])
			}
			if start < 1 || end > 65535 || start > end {
				return nil, fmt.Errorf("port range %d-%d out of valid range (1-65535)", start, end)
			}
			for p := start; p <= end; p++ {
				if !seen[p] {
					ports = append(ports, p)
					seen[p] = true
				}
			}
		} else {
			port, err := strconv.Atoi(part)
			if err != nil || port < 1 || port > 65535 {
				return nil, fmt.Errorf("invalid port: %s", part)
			}
			if !seen[port] {
				ports = append(ports, port)
				seen[port] = true
			}
		}
	}
	return ports, nil
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.Flags().StringP("target", "t", "", "Target to scan (e.g., scanme.nmap.org, example.com)")
	scanCmd.Flags().StringP("type", "y", "network", "Scan type (network, web)")
	scanCmd.Flags().StringP("ports", "p", "22,80,443", "Ports to scan (e.g., 22,80,443 or 20-25,80)")
	scanCmd.Flags().StringP("format", "f", "table", "Output format (table, json, yaml)")
	scanCmd.Flags().StringP("output", "o", "", "Output file (e.g., results.json, results.yaml, results.csv)")
}