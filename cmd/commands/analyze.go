package commands

import (
	"fmt"
	"os"

	"github.com/shieldcli/shieldcli/pkg/gemini"
	"github.com/shieldcli/shieldcli/pkg/logging"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var analyzeCmd = &cobra.Command{
	Use:   "analyze",
	Short: "Analyze payloads and logs using AI",
	Long:  `Use Gemini AI to analyze suspicious payloads and logs`,
}

var analyzePayloadCmd = &cobra.Command{
	Use:   "payload [payload_string]",
	Short: "Analyze a suspicious payload",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return analyzePayload(args[0])
	},
}

var analyzeLogCmd = &cobra.Command{
	Use:   "log",
	Short: "Summarize attack trends from a log file",
	RunE: func(cmd *cobra.Command, args []string) error {
		return analyzeLog()
	},
}

var (
	logFilePath string
)

func init() {
	analyzeCmd.AddCommand(analyzePayloadCmd)
	analyzeCmd.AddCommand(analyzeLogCmd)

	analyzeLogCmd.Flags().StringVar(&logFilePath, "log-file", "", "Path to the WAF log file")
	analyzeLogCmd.MarkFlagRequired("log-file")
}

func analyzePayload(payload string) error {
	// Get Gemini API key
	geminiKey := os.Getenv("GEMINI_API_KEY")
	if geminiKey == "" {
		geminiKey = viper.GetString("gemini.api_key")
	}

	if geminiKey == "" {
		return fmt.Errorf("Gemini API key not found. Set GEMINI_API_KEY environment variable or configure it in shieldcli.yaml")
	}

	// Create logger
	logger := logging.NewLogger("")
	defer logger.Close()

	// Create Gemini client
	model := viper.GetString("gemini.model")
	if model == "" {
		model = "gemini-2.5-flash"
	}

	client, err := gemini.NewClient(geminiKey, model, logger)
	if err != nil {
		logger.Error("Failed to create Gemini client: %v", err)
		return err
	}
	defer client.Close()

	logger.Info("Analyzing payload with Gemini AI...")

	// Analyze the payload
	result, err := client.AnalyzePayload(payload)
	if err != nil {
		logger.Error("Failed to analyze payload: %v", err)
		return err
	}

	// Display results
	fmt.Println("\n=== Payload Analysis Results ===")
	fmt.Printf("Verdict: %s\n", result.Verdict)
	fmt.Printf("Confidence: %.2f%%\n", result.Confidence*100)
	fmt.Printf("Explanation: %s\n", result.Explanation)

	if result.SuggestedRule != "" {
		fmt.Printf("Suggested Rule: %s\n", result.SuggestedRule)
	}

	if result.IsMalicious {
		fmt.Println("\n⚠️  This payload appears to be MALICIOUS!")
	} else {
		fmt.Println("\n✓ This payload appears to be SAFE.")
	}

	return nil
}

func analyzeLog() error {
	// Get Gemini API key
	geminiKey := os.Getenv("GEMINI_API_KEY")
	if geminiKey == "" {
		geminiKey = viper.GetString("gemini.api_key")
	}

	if geminiKey == "" {
		return fmt.Errorf("Gemini API key not found. Set GEMINI_API_KEY environment variable or configure it in shieldcli.yaml")
	}

	// Create logger
	logger := logging.NewLogger("")
	defer logger.Close()

	// Read log file
	logData, err := os.ReadFile(logFilePath)
	if err != nil {
		logger.Error("Failed to read log file: %v", err)
		return err
	}

	// Create Gemini client
	model := viper.GetString("gemini.model")
	if model == "" {
		model = "gemini-2.5-flash"
	}

	client, err := gemini.NewClient(geminiKey, model, logger)
	if err != nil {
		logger.Error("Failed to create Gemini client: %v", err)
		return err
	}
	defer client.Close()

	logger.Info("Summarizing attack trends...")

	// Summarize attacks
	summary, err := client.SummarizeAttacks(string(logData))
	if err != nil {
		logger.Error("Failed to summarize attacks: %v", err)
		return err
	}

	// Display results
	fmt.Println("\n=== Attack Trends Summary ===")
	fmt.Println(summary)

	return nil
}
