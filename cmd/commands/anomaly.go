package commands

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/shieldcli/shieldcli/pkg/anomaly"
	"github.com/spf13/cobra"
)

var anomalyCmd = &cobra.Command{
	Use:   "anomaly",
	Short: "Analyze traffic anomalies and statistics",
	Long:  `Analyze traffic anomalies using statistical methods for research and threat detection`,
}

var anomalyReportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate an anomaly detection report",
	RunE: func(cmd *cobra.Command, args []string) error {
		return generateAnomalyReport()
	},
}

var anomalyStatsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Display traffic statistics",
	RunE: func(cmd *cobra.Command, args []string) error {
		return displayAnomalyStats()
	},
}

func init() {
	anomalyCmd.AddCommand(anomalyReportCmd)
	anomalyCmd.AddCommand(anomalyStatsCmd)
}

func generateAnomalyReport() error {
	// Create a detector with a 1-minute window
	detector := anomaly.NewAnomalyDetector(60 * 60) // 1 hour window

	// Get all anomalies
	anomalies := detector.GetAnomalies()

	if len(anomalies) == 0 {
		fmt.Println("No anomalies detected.")
		return nil
	}

	fmt.Println("\n=== Anomaly Detection Report ===")
	fmt.Printf("Total Anomalies Detected: %d\n\n", len(anomalies))

	// Display anomalies by severity
	severities := []string{"critical", "high", "medium", "low"}
	for _, severity := range severities {
		var severityAnomalies []anomaly.Anomaly
		for _, a := range anomalies {
			if a.Severity == severity {
				severityAnomalies = append(severityAnomalies, a)
			}
		}

		if len(severityAnomalies) > 0 {
			fmt.Printf("\n%s Severity Anomalies (%d):\n", severity, len(severityAnomalies))
			fmt.Println("---")

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "Type\tValue\tThreshold\tDescription")
			fmt.Fprintln(w, "----\t-----\t---------\t-----------")

			for _, a := range severityAnomalies {
				fmt.Fprintf(w, "%s\t%.2f\t%.2f\t%s\n",
					a.Type, a.Value, a.Threshold, a.Description)
			}
			w.Flush()
		}
	}

	return nil
}

func displayAnomalyStats() error {
	detector := anomaly.NewAnomalyDetector(60 * 60)
	stats := detector.GetStatistics()

	fmt.Println("\n=== Traffic Statistics ===")
	fmt.Printf("Total Requests: %v\n", stats["total_requests"])
	fmt.Printf("Unique IPs: %v\n", stats["unique_ips"])
	fmt.Printf("Unique User Agents: %v\n", stats["unique_user_agents"])
	fmt.Printf("Average Payload Size: %.2f bytes\n", stats["avg_payload_size"])
	fmt.Printf("Average Entropy: %.2f\n", stats["avg_entropy"])
	fmt.Printf("Large Payloads: %v\n", stats["large_payloads"])
	fmt.Printf("Encoded Payloads: %v\n", stats["encoded_payloads"])
	fmt.Printf("Total Anomalies: %v\n", stats["total_anomalies"])

	return nil
}
