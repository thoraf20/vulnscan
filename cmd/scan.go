package cmd

import (
    "fmt"
    "github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
    Use:   "scan",
    Short: "Scan a target for vulnerabilities",
    Run: func(cmd *cobra.Command, args []string) {
        target, _ := cmd.Flags().GetString("target")
        if target == "" {
            fmt.Println("Error: --target is required")
            cmd.Usage()
            return
        }
        fmt.Printf("Starting scan on %s...\n", target)
    },
}

func init() {
    rootCmd.AddCommand(scanCmd)
}