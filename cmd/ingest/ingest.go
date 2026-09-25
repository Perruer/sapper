package ingest

import (
	"github.com/Perruer/sapper/cmd/ingest/data"
	"github.com/Perruer/sapper/cmd/ingest/osv"
	"github.com/Perruer/sapper/cmd/ingest/sbom"
	"github.com/Perruer/sapper/cmd/ingest/scorecard"
	"github.com/spf13/cobra"
)

type options struct{}

func (o *options) AddFlags(_ *cobra.Command) {
}

func New() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "ingest",
		Short:             "ingest metadata into the graph",
		SilenceUsage:      true,
		DisableAutoGenTag: true,
	}

	cmd.AddCommand(osv.New())
	cmd.AddCommand(sbom.New())
	cmd.AddCommand(scorecard.New())
	cmd.AddCommand(data.NewKEV())
	cmd.AddCommand(data.NewEPSS())
	cmd.AddCommand(data.NewVEX())
	return cmd
}
