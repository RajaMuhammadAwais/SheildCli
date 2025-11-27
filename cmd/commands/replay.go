package commands

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/shieldcli/shieldcli/pkg/replay"
	"github.com/spf13/cobra"
)

var replayCmd = &cobra.Command{
	Use:   "replay",
	Short: "Record and replay HTTP traffic for reproducible testing",
	Long:  `Record HTTP traffic and replay it against a target server for reproducible attack simulation`,
}

var replayRecordCmd = &cobra.Command{
	Use:   "record",
	Short: "Record HTTP traffic",
	RunE: func(cmd *cobra.Command, args []string) error {
		return recordTraffic()
	},
}

var replayPlayCmd = &cobra.Command{
	Use:   "play",
	Short: "Replay recorded traffic",
	RunE: func(cmd *cobra.Command, args []string) error {
		return playTraffic()
	},
}

var replayExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export recorded traffic to CSV",
	RunE: func(cmd *cobra.Command, args []string) error {
		return exportTraffic()
	},
}

var (
	recordFile string
	targetURL  string
	exportFile string
)

func init() {
	replayCmd.AddCommand(replayRecordCmd)
	replayCmd.AddCommand(replayPlayCmd)
	replayCmd.AddCommand(replayExportCmd)

	replayRecordCmd.Flags().StringVar(&recordFile, "output", "traffic.json", "Output file for recorded traffic")
	replayPlayCmd.Flags().StringVar(&recordFile, "input", "traffic.json", "Input file with recorded traffic")
	replayPlayCmd.Flags().StringVar(&targetURL, "target", "http://localhost:3000", "Target URL for replay")
	replayExportCmd.Flags().StringVar(&recordFile, "input", "traffic.json", "Input file with recorded traffic")
	replayExportCmd.Flags().StringVar(&exportFile, "output", "traffic.csv", "Output CSV file")
}

func recordTraffic() error {
	fmt.Printf("Recording traffic to: %s\n", recordFile)
	fmt.Println("Traffic recording is integrated into the proxy. Use 'shieldcli run --record-file <file>' to enable recording.")
	fmt.Println("\nExample:")
	fmt.Println("  ./shieldcli run --proxy-to http://localhost:3000 --port 8080 --record-file traffic.json")
	return nil
}

func playTraffic() error {
	// Load recorded traffic
	recorder := replay.NewRecorder(recordFile, 10000)
	if err := recorder.LoadFromFile(); err != nil {
		fmt.Printf("Error loading traffic file: %v\n", err)
		return err
	}

	records := recorder.GetRecords()
	fmt.Printf("Loaded %d recorded requests\n", len(records))

	// Create replayer
	replayer := replay.NewReplayer(targetURL)
	replayer.LoadRecords(records)

	fmt.Printf("Replaying traffic against: %s\n", targetURL)

	// Replay all requests
	if err := replayer.ReplayAll(); err != nil {
		fmt.Printf("Error during replay: %v\n", err)
		return err
	}

	// Display results
	results := replayer.GetResults()
	summary := replayer.GetResultSummary()

	fmt.Println("\n=== Replay Results ===")
	fmt.Printf("Total Requests: %v\n", summary["total_requests"])
	fmt.Printf("Successful Requests: %v\n", summary["successful_requests"])
	fmt.Printf("Status Matches: %v\n", summary["status_matches"])
	fmt.Printf("Body Matches: %v\n", summary["body_matches"])
	fmt.Printf("Success Rate: %.2f%%\n", summary["success_rate"])
	fmt.Printf("Average Duration: %v\n", summary["average_duration"])

	// Display detailed results
	fmt.Println("\n=== Detailed Results ===")
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "Method\tURL\tOriginal Status\tReplayed Status\tMatch\tDuration")
	fmt.Fprintln(w, "------\t---\t---------------\t---------------\t-----\t--------")

	for _, result := range results {
		match := "✓"
		if !result.StatusMatch {
			match = "✗"
		}
		fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%s\t%v\n",
			result.OriginalRequest.Method,
			result.OriginalRequest.URL,
			result.OriginalResponse.StatusCode,
			result.ReplayedResponse.StatusCode,
			match,
			result.ReplayedResponse.Duration,
		)
	}
	w.Flush()

	return nil
}

func exportTraffic() error {
	// Load recorded traffic
	recorder := replay.NewRecorder(recordFile, 10000)
	if err := recorder.LoadFromFile(); err != nil {
		fmt.Printf("Error loading traffic file: %v\n", err)
		return err
	}

	// Export to CSV
	if err := recorder.ExportToCSV(exportFile); err != nil {
		fmt.Printf("Error exporting to CSV: %v\n", err)
		return err
	}

	fmt.Printf("Traffic exported to: %s\n", exportFile)
	fmt.Printf("Total records: %d\n", recorder.GetRecordCount())

	return nil
}
