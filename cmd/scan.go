package cmd

import (
    "github.com/spf13/cobra"
    "github.com/thoraf20/vulnscan/internal/config"
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
        log.Infof("Starting %s scan on %s...\n", scanType, target)
    },
}

func init() {
    rootCmd.AddCommand(scanCmd)
    scanCmd.Flags().StringP("type", "y", "network", "Scan type (network, web)")
}