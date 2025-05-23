/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"os"
	"github.com/spf13/cobra"
)


// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "VulnScan",
	Short: "VulnScan is a security audit and vulnerability assessment tool",
	Long: `A fast, open-source tool built in Go to scan networks, web apps, and code for vulnerabilities.`,
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	rootCmd.PersistentFlags().StringP("target", "t", "", "Target to scan (e.g., example.com)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
// 	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}


