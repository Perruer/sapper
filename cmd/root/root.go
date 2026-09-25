package root

import (
	"context"
	"fmt"
	"net/http"

	"github.com/Perruer/sapper/cmd/cache"
	"github.com/Perruer/sapper/cmd/ingest"
	"github.com/Perruer/sapper/cmd/leaderboard"
	llm "github.com/Perruer/sapper/cmd/llm"
	"github.com/Perruer/sapper/cmd/query"
	"github.com/Perruer/sapper/cmd/report"
	"github.com/Perruer/sapper/cmd/server"
	"github.com/spf13/cobra"
)

// Version is set at build time with -ldflags "-X github.com/Perruer/sapper/cmd/root.Version=...".
var Version = "dev"

type options struct {
	PprofAddr    string
	PprofEnabled bool
}

func (o *options) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().BoolVar(&o.PprofEnabled, "pprof", false, "Enable pprof server")
	cmd.PersistentFlags().StringVar(&o.PprofAddr, "pprof-addr", "localhost:6060", "Address for pprof server")
}

func New() *cobra.Command {
	o := &options{}
	rootCmd := &cobra.Command{
		Use:               "sapper",
		Version:           Version,
		Short:             "Find where vulnerable packages sit across all of your products",
		SilenceUsage:      true,
		DisableAutoGenTag: true,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			o.AddFlags(cmd)
			if o.PprofEnabled {
				srv := &http.Server{Addr: o.PprofAddr}
				go func() {
					fmt.Printf("Starting pprof server on %s\n", o.PprofAddr)
					if err := srv.ListenAndServe(); err != http.ErrServerClosed {
						fmt.Printf("pprof server error: %v\n", err)
					}
				}()
				cmd.PersistentPostRun = func(cmd *cobra.Command, args []string) {
					if err := srv.Shutdown(context.Background()); err != nil {
						fmt.Printf("pprof server shutdown error: %v\n", err)
					}
				}
			}
		},
	}

	rootCmd.AddCommand(query.New())
	rootCmd.AddCommand(ingest.New())
	rootCmd.AddCommand(cache.New())
	rootCmd.AddCommand(leaderboard.New())
	rootCmd.AddCommand(server.New())
	rootCmd.AddCommand(llm.New())
	rootCmd.AddCommand(report.New())
	rootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print the version of Sapper",
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintln(cmd.OutOrStdout(), "sapper", Version)
		},
	})
	return rootCmd
}
