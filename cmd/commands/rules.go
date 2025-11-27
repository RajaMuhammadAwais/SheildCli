package commands

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/shieldcli/shieldcli/pkg/config"
	"github.com/shieldcli/shieldcli/pkg/logging"
	"github.com/shieldcli/shieldcli/pkg/waf"
	"github.com/spf13/cobra"
)

var rulesCmd = &cobra.Command{
	Use:   "rules",
	Short: "Manage custom WAF rules",
	Long:  `Manage custom WAF rules for ShieldCLI`,
}

var rulesAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a new custom WAF rule",
	RunE: func(cmd *cobra.Command, args []string) error {
		return rulesAdd()
	},
}

var rulesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all active custom rules",
	RunE: func(cmd *cobra.Command, args []string) error {
		return rulesList()
	},
}

var (
	ruleID          int
	ruleName        string
	ruleDescription string
	rulePhase       string
	ruleOperator    string
	rulePattern     string
	ruleTarget      string
	ruleAction      string
	ruleSeverity    string
)

func init() {
	rulesCmd.AddCommand(rulesAddCmd)
	rulesCmd.AddCommand(rulesListCmd)

	rulesAddCmd.Flags().IntVar(&ruleID, "id", 0, "Rule ID")
	rulesAddCmd.Flags().StringVar(&ruleName, "name", "", "Rule name")
	rulesAddCmd.Flags().StringVar(&ruleDescription, "description", "", "Rule description")
	rulesAddCmd.Flags().StringVar(&rulePhase, "phase", "request_body", "Rule phase (request_headers, request_uri, request_body)")
	rulesAddCmd.Flags().StringVar(&ruleOperator, "operator", "contains", "Rule operator (contains, regex, startswith, endswith, equals, sqli, xss)")
	rulesAddCmd.Flags().StringVar(&rulePattern, "pattern", "", "Rule pattern")
	rulesAddCmd.Flags().StringVar(&ruleTarget, "target", "REQUEST_BODY", "Rule target (REQUEST_URI, REQUEST_HEADERS, REQUEST_BODY, ARGS)")
	rulesAddCmd.Flags().StringVar(&ruleAction, "action", "block", "Rule action (block, log, pass)")
	rulesAddCmd.Flags().StringVar(&ruleSeverity, "severity", "medium", "Rule severity (low, medium, high, critical)")

	rulesAddCmd.MarkFlagRequired("id")
	rulesAddCmd.MarkFlagRequired("name")
	rulesAddCmd.MarkFlagRequired("pattern")
}

func rulesAdd() error {
	fmt.Println("Rule Management - Add Rule")
	fmt.Println("===========================")
	fmt.Printf("Rule ID: %d\n", ruleID)
	fmt.Printf("Name: %s\n", ruleName)
	fmt.Printf("Description: %s\n", ruleDescription)
	fmt.Printf("Phase: %s\n", rulePhase)
	fmt.Printf("Operator: %s\n", ruleOperator)
	fmt.Printf("Pattern: %s\n", rulePattern)
	fmt.Printf("Target: %s\n", ruleTarget)
	fmt.Printf("Action: %s\n", ruleAction)
	fmt.Printf("Severity: %s\n", ruleSeverity)

	// Create rule object
	rule := &waf.Rule{
		ID:          ruleID,
		Name:        ruleName,
		Description: ruleDescription,
		Phase:       waf.RulePhase(rulePhase),
		Operator:    waf.RuleOperator(ruleOperator),
		Pattern:     rulePattern,
		Target:      ruleTarget,
		Action:      waf.RuleAction(ruleAction),
		Severity:    ruleSeverity,
		Enabled:     true,
	}

	// Compile the rule
	if err := rule.Compile(); err != nil {
		fmt.Printf("Error: Failed to compile rule: %v\n", err)
		return err
	}

	fmt.Println("\n✓ Rule created successfully!")
	fmt.Println("Note: This rule is not yet saved to configuration. Use 'config init' to save it.")

	return nil
}

func rulesList() error {
	// Create a temporary WAF engine to get default rules
	logger := &logging.Logger{}
	cfg := &config.Config{}

	engine, err := waf.NewEngine(cfg, logger)
	if err != nil {
		fmt.Printf("Error: Failed to create WAF engine: %v\n", err)
		return err
	}

	rules := engine.GetRules()

	if len(rules) == 0 {
		fmt.Println("No rules found.")
		return nil
	}

	// Display rules in a table
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tNAME\tPHASE\tOPERATOR\tTARGET\tACTION\tSEVERITY\tSTATUS")
	fmt.Fprintln(w, "--\t----\t-----\t--------\t------\t------\t--------\t------")

	for _, rule := range rules {
		status := "enabled"
		if !rule.Enabled {
			status = "disabled"
		}
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			rule.ID, rule.Name, rule.Phase, rule.Operator, rule.Target, rule.Action, rule.Severity, status)
	}

	w.Flush()

	fmt.Printf("\nTotal: %d rules\n", len(rules))
	return nil
}


