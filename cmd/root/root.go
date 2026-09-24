package root

import (
	"context"
	"fmt"
	"net/http"

	"github.com/Perruer/sapper/cmd/cache"
	"github.com/Perruer/sapper/cmd/ingest"
	"github.com/Perruer/sapper/cmd/leaderboard"
	"github.com/Perruer/sapper/cmd/query"
	"github.com/Perruer/sapper/cmd/server"
	llm "github.com/Perruer/sapper/cmd/llm"
	"github.com/spf13/cobra"
)

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
		Short:             "Graphing SBOM's with the power of roaring bitmaps",
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
	return rootCmd
}
