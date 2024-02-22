package main

import (
	"fmt"
	"github.com/pinax-network/firehose-beacon/cmd/firebeacon/http"
	"github.com/spf13/cobra"
	"github.com/streamingfast/firehose-core/cmd/tools"
	"github.com/streamingfast/logging"
	"go.uber.org/zap"
	"os"
)

var logger, tracer = logging.PackageLogger("firebeacon", "github.com/pinax-network/firehose-beacon")
var rootCmd = &cobra.Command{
	Use:   "firebeacon",
	Short: "firebeacon fetching and tooling",
}

func init() {
	logging.InstantiateLoggers(logging.WithDefaultLevel(zap.InfoLevel))
	rootCmd.AddCommand(newFetchCmd(logger, tracer))

	rootCmd.AddCommand(tools.ToolsCmd)
}

func main() {

	if err := rootCmd.Execute(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Whoops. There was an error while executing your CLI '%s'", err)
		os.Exit(1)
	}
}

func newFetchCmd(logger *zap.Logger, tracer logging.Tracer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fetch",
		Short: "fetch blocks from different sources",
		Args:  cobra.ExactArgs(2),
	}
	cmd.AddCommand(http.NewFetchCmd(logger, tracer))
	return cmd
}
