package cmd

import (
    "github.com/spf13/cobra"
    "github.com/thoraf20/vulnscan/internal/config"
    "github.com/thoraf20/vulnscan/pkg/scanner"
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
            result := scanner.ScanTCPPort(target, 80) // Test port 80 (HTTP)
            if result.Open {
                log.Infof("Port %d is open on %s", result.Port, target)
            } else {
                log.Warnf("Port %d is closed or filtered on %s", result.Port, target)
            }
        } else {
            log.Infof("Web scan on %s not implemented yet", target)
        }
    },
}

func init() {
    rootCmd.AddCommand(scanCmd)
    scanCmd.Flags().StringP("type", "y", "network", "Scan type (network, web)")
}