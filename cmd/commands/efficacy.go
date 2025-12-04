package commands

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/spf13/cobra"
	"github.com/shieldcli/shieldcli/pkg/analysis"
	"github.com/shieldcli/shieldcli/pkg/logging"
)

var efficacyCmd = &cobra.Command{
	Use:   "efficacy",
	Short: "Analyze WAF rule efficacy and performance metrics",
	Long: `Analyze the effectiveness of WAF rules using structured logs.
	
This command provides detailed metrics on rule performance including:
- Precision, recall, and F1-score
- False positive rates
- Attack pattern analysis
- Performance recommendations`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

var efficacyReportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate a comprehensive rule efficacy report",
	Long:  "Analyze structured logs and generate a detailed report on rule performance",
	RunE: func(cmd *cobra.Command, args []string) error {
		logFile, _ := cmd.Flags().GetString("log-file")
		outputFile, _ := cmd.Flags().GetString("output")
		format, _ := cmd.Flags().GetString("format")

		if logFile == "" {
			return fmt.Errorf("--log-file is required")
		}

		// Load events from log file
		events, err := loadEventsFromFile(logFile)
		if err != nil {
			return fmt.Errorf("failed to load events: %w", err)
		}

		// Create analyzer and add events
		analyzer := analysis.NewEfficacyAnalyzer()
		for _, event := range events {
			analyzer.AddEvent(event)
		}

		// Perform analysis
		if err := analyzer.AnalyzeRules(); err != nil {
			return fmt.Errorf("analysis failed: %w", err)
		}

		// Generate report
		report := generateReport(analyzer)

		// Output report
		switch format {
		case "json":
			data, _ := json.MarshalIndent(report, "", "  ")
			output := string(data)
			if outputFile != "" {
				os.WriteFile(outputFile, []byte(output), 0644)
				fmt.Printf("Report saved to: %s\n", outputFile)
			} else {
				fmt.Println(output)
			}

		case "text":
			output := formatReportAsText(report)
			if outputFile != "" {
				os.WriteFile(outputFile, []byte(output), 0644)
				fmt.Printf("Report saved to: %s\n", outputFile)
			} else {
				fmt.Println(output)
			}

		case "csv":
			output := formatReportAsCSV(report)
			if outputFile != "" {
				os.WriteFile(outputFile, []byte(output), 0644)
				fmt.Printf("Report saved to: %s\n", outputFile)
			} else {
				fmt.Println(output)
			}

		default:
			return fmt.Errorf("unsupported format: %s", format)
		}

		return nil
	},
}

var efficacyCompareCmd = &cobra.Command{
	Use:   "compare <rule_id_1> <rule_id_2>",
	Short: "Compare performance of two rules",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		logFile, _ := cmd.Flags().GetString("log-file")
		if logFile == "" {
			return fmt.Errorf("--log-file is required")
		}

		// Load events
		events, err := loadEventsFromFile(logFile)
		if err != nil {
			return fmt.Errorf("failed to load events: %w", err)
		}

		// Create analyzer
		analyzer := analysis.NewEfficacyAnalyzer()
		for _, event := range events {
			analyzer.AddEvent(event)
		}

		if err := analyzer.AnalyzeRules(); err != nil {
			return fmt.Errorf("analysis failed: %w", err)
		}

		// Compare rules
		comparison := analyzer.CompareRules(args[0], args[1])
		if comparison == nil {
			return fmt.Errorf("one or both rules not found")
		}

		data, _ := json.MarshalIndent(comparison, "", "  ")
		fmt.Println(string(data))

		return nil
	},
}

var efficacyProblematicCmd = &cobra.Command{
	Use:   "problematic",
	Short: "Identify rules with high false positive rates",
	RunE: func(cmd *cobra.Command, args []string) error {
		logFile, _ := cmd.Flags().GetString("log-file")
		if logFile == "" {
			return fmt.Errorf("--log-file is required")
		}

		// Load events
		events, err := loadEventsFromFile(logFile)
		if err != nil {
			return fmt.Errorf("failed to load events: %w", err)
		}

		// Create analyzer
		analyzer := analysis.NewEfficacyAnalyzer()
		for _, event := range events {
			analyzer.AddEvent(event)
		}

		if err := analyzer.AnalyzeRules(); err != nil {
			return fmt.Errorf("analysis failed: %w", err)
		}

		// Get problematic rules
		problematic := analyzer.GetProblematicRules()

		fmt.Printf("\n🔴 Problematic Rules (High False Positive Rate)\n")
		fmt.Println("=" * 80)

		for i, metrics := range problematic {
			fmt.Printf("\n%d. %s (ID: %s)\n", i+1, metrics.RuleName, metrics.RuleID)
			fmt.Printf("   Precision:       %.2f%%\n", metrics.Precision*100)
			fmt.Printf("   False Positives: %d\n", metrics.FalsePositives)
			fmt.Printf("   Block Rate:      %.2f%%\n", metrics.BlockRate)

			if len(metrics.Recommendations) > 0 {
				fmt.Println("   Recommendations:")
				for _, rec := range metrics.Recommendations {
					fmt.Printf("   - %s\n", rec)
				}
			}
		}

		return nil
	},
}

var efficacyTopCmd = &cobra.Command{
	Use:   "top [count]",
	Short: "Show top performing rules",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		logFile, _ := cmd.Flags().GetString("log-file")
		if logFile == "" {
			return fmt.Errorf("--log-file is required")
		}

		count := 10
		if len(args) > 0 {
			var err error
			count, err = strconv.Atoi(args[0])
			if err != nil {
				return fmt.Errorf("invalid count: %s", args[0])
			}
		}

		// Load events
		events, err := loadEventsFromFile(logFile)
		if err != nil {
			return fmt.Errorf("failed to load events: %w", err)
		}

		// Create analyzer
		analyzer := analysis.NewEfficacyAnalyzer()
		for _, event := range events {
			analyzer.AddEvent(event)
		}

		if err := analyzer.AnalyzeRules(); err != nil {
			return fmt.Errorf("analysis failed: %w", err)
		}

		// Get top rules
		topRules := analyzer.GetTopRules(count)

		fmt.Printf("\n🏆 Top %d Performing Rules (by F1-Score)\n", count)
		fmt.Println("=" * 80)

		for i, metrics := range topRules {
			fmt.Printf("\n%d. %s (ID: %s)\n", i+1, metrics.RuleName, metrics.RuleID)
			fmt.Printf("   F1-Score:   %.4f\n", metrics.F1Score)
			fmt.Printf("   Precision:  %.2f%%\n", metrics.Precision*100)
			fmt.Printf("   Recall:     %.2f%%\n", metrics.Recall*100)
			fmt.Printf("   Block Rate: %.2f%%\n", metrics.BlockRate)
			fmt.Printf("   Triggers:   %d\n", metrics.TotalTriggers)
		}

		return nil
	},
}

// loadEventsFromFile loads events from a JSON log file
func loadEventsFromFile(filePath string) ([]map[string]interface{}, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var events []map[string]interface{}

	// Try to parse as JSON array first
	err = json.Unmarshal(data, &events)
	if err == nil {
		return events, nil
	}

	// Try to parse as JSONL (one JSON per line)
	lines := string(data)
	decoder := json.NewDecoder(os.Stdin)
	decoder.UseNumber()

	// Read from file instead
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	decoder = json.NewDecoder(file)
	for decoder.More() {
		var event map[string]interface{}
		if err := decoder.Decode(&event); err != nil {
			continue
		}
		events = append(events, event)
	}

	return events, nil
}

// generateReport creates a comprehensive report
func generateReport(analyzer *analysis.EfficacyAnalyzer) map[string]interface{} {
	return map[string]interface{}{
		"summary":  analyzer.GetSummary(),
		"rules":    analyzer.GetAllMetrics(),
		"top_10":   analyzer.GetTopRules(10),
		"problems": analyzer.GetProblematicRules(),
	}
}

// formatReportAsText formats the report as human-readable text
func formatReportAsText(report map[string]interface{}) string {
	output := "\n" + "=" * 80 + "\n"
	output += "RULE EFFICACY ANALYSIS REPORT\n"
	output += "=" * 80 + "\n\n"

	// Summary
	if summary, ok := report["summary"].(map[string]interface{}); ok {
		output += "SUMMARY\n"
		output += "-" * 40 + "\n"
		for key, value := range summary {
			output += fmt.Sprintf("%s: %v\n", key, value)
		}
		output += "\n"
	}

	// Top rules
	if top, ok := report["top_10"].([]interface{}); ok {
		output += fmt.Sprintf("TOP 10 RULES (by F1-Score)\n")
		output += "-" * 40 + "\n"
		for i, rule := range top {
			if m, ok := rule.(map[string]interface{}); ok {
				output += fmt.Sprintf("%d. %s (ID: %s)\n", i+1, m["rule_name"], m["rule_id"])
				output += fmt.Sprintf("   F1-Score: %.4f | Precision: %.2f%% | Recall: %.2f%%\n\n",
					m["f1_score"], m["precision"], m["recall"])
			}
		}
	}

	return output
}

// formatReportAsCSV formats the report as CSV
func formatReportAsCSV(report map[string]interface{}) string {
	output := "Rule ID,Rule Name,Total Triggers,True Positives,False Positives,Precision,Recall,F1-Score,Block Rate,Avg Latency\n"

	if rules, ok := report["rules"].(map[string]interface{}); ok {
		for _, ruleData := range rules {
			if m, ok := ruleData.(map[string]interface{}); ok {
				output += fmt.Sprintf("%s,%s,%v,%v,%v,%.4f,%.4f,%.4f,%.2f,%.2f\n",
					m["rule_id"],
					m["rule_name"],
					m["total_triggers"],
					m["true_positives"],
					m["false_positives"],
					m["precision"],
					m["recall"],
					m["f1_score"],
					m["block_rate"],
					m["avg_latency_ms"],
				)
			}
		}
	}

	return output
}

func init() {
	// Register subcommands
	efficacyCmd.AddCommand(efficacyReportCmd)
	efficacyCmd.AddCommand(efficacyCompareCmd)
	efficacyCmd.AddCommand(efficacyProblematicCmd)
	efficacyCmd.AddCommand(efficacyTopCmd)

	// Flags for report command
	efficacyReportCmd.Flags().StringP("log-file", "l", "", "Path to structured log file (JSON)")
	efficacyReportCmd.Flags().StringP("output", "o", "", "Output file path (optional)")
	efficacyReportCmd.Flags().StringP("format", "f", "json", "Output format: json, text, or csv")

	// Flags for compare command
	efficacyCompareCmd.Flags().StringP("log-file", "l", "", "Path to structured log file (JSON)")

	// Flags for problematic command
	efficacyProblematicCmd.Flags().StringP("log-file", "l", "", "Path to structured log file (JSON)")

	// Flags for top command
	efficacyTopCmd.Flags().StringP("log-file", "l", "", "Path to structured log file (JSON)")

	// Add to root command
	rootCmd.AddCommand(efficacyCmd)
}
