// Package data holds the commands that load prioritisation data: the CISA KEV catalog, EPSS scores
// and OpenVEX documents. They read local files, so they work in an air-gapped network too.
package data

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"connectrpc.com/connect"
	apiv1 "github.com/Perruer/sapper/gen/api/v1"
	"github.com/Perruer/sapper/gen/api/v1/apiv1connect"
	"github.com/spf13/cobra"
)

const defaultAddr = "http://localhost:8089"

type kind struct {
	use, short, long string
	call             func(apiv1connect.IngestServiceClient, context.Context, *connect.Request[apiv1.IngestDataRequest]) (*connect.Response[apiv1.IngestDataResponse], error)
	what             string
}

func newCommand(k kind) *cobra.Command {
	var addr string
	cmd := &cobra.Command{
		Use:               k.use,
		Short:             k.short,
		Long:              k.long,
		Args:              cobra.ExactArgs(1),
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			content, err := os.ReadFile(args[0])
			if err != nil {
				return fmt.Errorf("failed to read %s: %w", args[0], err)
			}
			client := apiv1connect.NewIngestServiceClient(http.DefaultClient, addr)
			resp, err := k.call(client, cmd.Context(), connect.NewRequest(&apiv1.IngestDataRequest{Data: content}))
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Stored %d %s\n", resp.Msg.Count, k.what)
			return nil
		},
	}
	cmd.Flags().StringVar(&addr, "addr", defaultAddr, "Address of the Sapper server")
	return cmd
}

// NewKEV loads the CISA Known Exploited Vulnerabilities catalog.
func NewKEV() *cobra.Command {
	return newCommand(kind{
		use:   "kev [known_exploited_vulnerabilities.json]",
		short: "Load the CISA Known Exploited Vulnerabilities catalog",
		long: `Load the CISA Known Exploited Vulnerabilities (KEV) catalog. Vulnerabilities in it are known to be
exploited and come first in reports.

Download: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`,
		call: func(c apiv1connect.IngestServiceClient, ctx context.Context, r *connect.Request[apiv1.IngestDataRequest]) (*connect.Response[apiv1.IngestDataResponse], error) {
			return c.IngestKEV(ctx, r)
		},
		what: "KEV entries",
	})
}

// NewEPSS loads a daily EPSS file.
func NewEPSS() *cobra.Command {
	return newCommand(kind{
		use:   "epss [epss_scores-YYYY-MM-DD.csv.gz]",
		short: "Load EPSS scores for the CVEs in the graph",
		long: `Load a daily EPSS file (the probability that a CVE is exploited in the next 30 days). Only the scores of
CVEs that the vulnerabilities in the graph refer to are stored, so load vulnerabilities first.

Download: https://epss.empiricalsecurity.com/epss_scores-current.csv.gz`,
		call: func(c apiv1connect.IngestServiceClient, ctx context.Context, r *connect.Request[apiv1.IngestDataRequest]) (*connect.Response[apiv1.IngestDataResponse], error) {
			return c.IngestEPSS(ctx, r)
		},
		what: "EPSS scores",
	})
}

// NewVEX loads an OpenVEX document.
func NewVEX() *cobra.Command {
	return newCommand(kind{
		use:   "vex [document.openvex.json]",
		short: "Load an OpenVEX document",
		long: `Load an OpenVEX document with statements such as "product X is not affected by CVE-Y". Products marked
not_affected or fixed are listed apart in reports.`,
		call: func(c apiv1connect.IngestServiceClient, ctx context.Context, r *connect.Request[apiv1.IngestDataRequest]) (*connect.Response[apiv1.IngestDataResponse], error) {
			return c.IngestVEX(ctx, r)
		},
		what: "VEX statements",
	})
}
