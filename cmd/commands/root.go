package commands

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile string
)

var rootCmd = &cobra.Command{
	Use:   "shieldcli",
	Short: "ShieldCLI - A terminal-first Web Application Firewall with AI-powered threat analysis",
	Long: `ShieldCLI is a lightweight, terminal-first Web Application Firewall that can be deployed 
on edge servers, developer machines, or containers to protect HTTP services in real time.
It features real-time traffic interception, rule-based blocking with OWASP Core Rule Set support,
and AI-powered threat analysis using Google's Gemini API.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Default to 'run' command if no subcommand is provided
		runCmd.Run(cmd, args)
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is ./shieldcli.yaml)")

	// Add subcommands
	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(rulesCmd)
	rootCmd.AddCommand(configCmd)
	rootCmd.AddCommand(analyzeCmd)
	rootCmd.AddCommand(anomalyCmd)
	rootCmd.AddCommand(replayCmd)
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Search for config in current directory
		viper.AddConfigPath(".")
		viper.SetConfigName("shieldcli")
		viper.SetConfigType("yaml")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it but don't fail if it's not found
	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}
