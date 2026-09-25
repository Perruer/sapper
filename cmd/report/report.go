// Package report prints which products each vulnerability reaches, most urgent first.
package report

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"connectrpc.com/connect"
	"github.com/Perruer/sapper/cmd/helpers"
	apiv1 "github.com/Perruer/sapper/gen/api/v1"
	"github.com/Perruer/sapper/gen/api/v1/apiv1connect"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"
)

type options struct {
	addr    string
	format  string
	kevOnly bool
	minEPSS float64
	limit   int
	client  apiv1connect.ReportServiceClient
}

func (o *options) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&o.addr, "addr", "http://localhost:8089", "Address of the Sapper server")
	cmd.Flags().StringVar(&o.format, "format", "table", "Output format: table, markdown or json")
	cmd.Flags().BoolVar(&o.kevOnly, "kev-only", false, "Only vulnerabilities in the CISA KEV catalog")
	cmd.Flags().Float64Var(&o.minEPSS, "min-epss", 0, "Only vulnerabilities with at least this EPSS score (0-1)")
	cmd.Flags().IntVar(&o.limit, "limit", 0, "Show at most this many vulnerabilities (0 for all)")
}

func (o *options) Run(cmd *cobra.Command, args []string) error {
	if o.client == nil {
		o.client = apiv1connect.NewReportServiceClient(http.DefaultClient, helpers.ServerURL(o.addr))
	}
	req := &apiv1.ReportRequest{KevOnly: o.kevOnly, MinEpss: o.minEPSS}
	if len(args) == 1 {
		req.Vulnerability = args[0]
	}
	resp, err := o.client.Report(cmd.Context(), connect.NewRequest(req))
	if err != nil {
		return fmt.Errorf("failed to get the report: %w", err)
	}
	findings := resp.Msg.Findings
	if o.limit > 0 && len(findings) > o.limit {
		findings = findings[:o.limit]
	}
	w := cmd.OutOrStdout()
	switch o.format {
	case "json":
		out, err := protojson.MarshalOptions{Multiline: true, Indent: "  "}.Marshal(&apiv1.ReportResponse{Findings: findings})
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(w, string(out))
		return err
	case "markdown", "md":
		return writeMarkdown(w, findings)
	case "table":
		return writeTable(w, findings)
	default:
		return fmt.Errorf("unknown format %q: use table, markdown or json", o.format)
	}
}

func writeTable(w io.Writer, findings []*apiv1.Finding) error {
	if len(findings) == 0 {
		_, err := fmt.Fprintln(w, "No vulnerabilities reach your products.")
		return err
	}
	table := helpers.NewTable(w, false)
	table.Header([]string{"Vulnerability", "Severity", "KEV", "EPSS", "Products", "Example path"})
	for _, f := range findings {
		kev := ""
		if f.Kev != nil {
			kev = "yes, due " + f.Kev.DueDate
		}
		epss := ""
		if f.Epss != nil {
			epss = fmt.Sprintf("%.3f", f.Epss.Epss)
		}
		path := ""
		if len(f.Products) > 0 {
			path = strings.Join(f.Products[0].Path, " > ")
		}
		products := fmt.Sprint(len(f.Products))
		if len(f.Suppressed) > 0 {
			products += fmt.Sprintf(" (+%d VEX)", len(f.Suppressed))
		}
		if err := table.Append([]string{title(f), severityLabel(f.Severity), kev, epss, products, path}); err != nil {
			return err
		}
	}
	return table.Render()
}

func writeMarkdown(w io.Writer, findings []*apiv1.Finding) error {
	var b strings.Builder
	b.WriteString("# Vulnerability report\n\n")
	if len(findings) == 0 {
		b.WriteString("No vulnerabilities reach your products.\n")
	}
	for _, f := range findings {
		fmt.Fprintf(&b, "## %s\n\n", title(f))
		if f.Summary != "" {
			fmt.Fprintf(&b, "%s\n\n", f.Summary)
		}
		if f.Severity != "" {
			fmt.Fprintf(&b, "- Severity: %s\n", f.Severity)
		}
		if f.Kev != nil {
			fmt.Fprintf(&b, "- **Known exploited** (CISA KEV since %s, action due %s", f.Kev.DateAdded, f.Kev.DueDate)
			if strings.EqualFold(f.Kev.KnownRansomwareCampaignUse, "Known") {
				b.WriteString(", used in ransomware campaigns")
			}
			b.WriteString(")\n")
		}
		if f.Epss != nil {
			fmt.Fprintf(&b, "- EPSS: %.3f (percentile %.2f", f.Epss.Epss, f.Epss.Percentile)
			if f.Epss.Date != "" {
				fmt.Fprintf(&b, ", %s", f.Epss.Date)
			}
			b.WriteString(")\n")
		}
		if len(f.Packages) > 0 {
			fmt.Fprintf(&b, "- Vulnerable packages: %s\n", "`"+strings.Join(f.Packages, "`, `")+"`")
		}
		fmt.Fprintf(&b, "\n**Affected products (%d)**\n\n", len(f.Products))
		for _, p := range f.Products {
			fmt.Fprintf(&b, "- `%s` via %s", p.Name, strings.Join(p.Path, " → "))
			if p.Vex != nil {
				fmt.Fprintf(&b, " (VEX: %s)", p.Vex.Status)
			}
			b.WriteString("\n")
		}
		if len(f.Suppressed) > 0 {
			fmt.Fprintf(&b, "\n**Not affected or fixed according to VEX (%d)**\n\n", len(f.Suppressed))
			for _, p := range f.Suppressed {
				fmt.Fprintf(&b, "- `%s`: %s", p.Name, p.Vex.Status)
				if p.Vex.Justification != "" {
					fmt.Fprintf(&b, " (%s)", p.Vex.Justification)
				}
				b.WriteString("\n")
			}
		}
		b.WriteString("\n")
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func title(f *apiv1.Finding) string {
	for _, a := range f.Aliases {
		if strings.HasPrefix(strings.ToUpper(a), "CVE-") && !strings.EqualFold(a, f.Id) {
			return f.Id + " / " + a
		}
	}
	return f.Id
}

// severityLabel shortens a CVSS vector to its version; labels such as HIGH pass through.
func severityLabel(s string) string {
	if strings.HasPrefix(s, "CVSS:") {
		if version, _, ok := strings.Cut(s, "/"); ok {
			return version
		}
	}
	return s
}

func New() *cobra.Command {
	o := &options{}
	cmd := &cobra.Command{
		Use:   "report [vulnerability ID or CVE]",
		Short: "Show which products each vulnerability reaches, most urgent first",
		Long: `Show the vulnerabilities in the graph with the products they reach and one dependency path to each.
Vulnerabilities in the CISA KEV catalog come first, then those with the highest EPSS score, then those that
reach the most products. Products that a VEX statement marks not_affected or fixed are listed apart.

Load SBOMs and vulnerabilities first (sapper ingest sbom / osv), and optionally KEV, EPSS and VEX data.`,
		Args:              cobra.MaximumNArgs(1),
		RunE:              o.Run,
		DisableAutoGenTag: true,
	}
	o.AddFlags(cmd)
	return cmd
}
