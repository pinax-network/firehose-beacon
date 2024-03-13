package http

import (
	"fmt"
	"github.com/attestantio/go-eth2-client/http"
	"github.com/pinax-network/firehose-beacon/blockfetcher"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"github.com/streamingfast/cli/sflags"
	firecore "github.com/streamingfast/firehose-core"
	"github.com/streamingfast/firehose-core/blockpoller"
	"github.com/streamingfast/logging"
	"go.uber.org/zap"
	"strconv"
	"time"
)

func NewFetchCmd(logger *zap.Logger, tracer logging.Tracer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "http <http-endpoint> <first-streamable-block>",
		Short: "fetch blocks from Lighthouse api endpoint",
		Args:  cobra.ExactArgs(2),
		RunE:  fetchRunE(logger, tracer),
	}

	cmd.Flags().String("state-dir", "/data/poller", "directory to store the sync state")
	cmd.Flags().Duration("interval-between-fetch", 0, "interval between fetch")
	cmd.Flags().Duration("latest-block-retry-interval", time.Second, "interval between fetch")
	cmd.Flags().Int("block-fetch-batch-size", 10, "Number of blocks to fetch in a single batch")
	cmd.Flags().Duration("http-timeout", 10*time.Second, "Timeout for http calls to the Lighthouse api")

	return cmd
}

func fetchRunE(logger *zap.Logger, tracer logging.Tracer) firecore.CommandExecutor {
	return func(cmd *cobra.Command, args []string) (err error) {
		ctx := cmd.Context()
		httpEndpoint := args[0]

		stateDir := sflags.MustGetString(cmd, "state-dir")

		startBlock, err := strconv.ParseUint(args[1], 10, 64)
		if err != nil {
			return fmt.Errorf("unable to parse first streamable block %d: %w", startBlock, err)
		}

		fetchInterval := sflags.MustGetDuration(cmd, "interval-between-fetch")

		logger.Info(
			"launching firehose-beacon poller",
			zap.String("http_endpoint", httpEndpoint),
			zap.String("state_dir", stateDir),
			zap.Uint64("first_streamable_block", startBlock),
			zap.Duration("interval_between_fetch", fetchInterval),
			zap.Duration("latest_block_retry_interval", sflags.MustGetDuration(cmd, "latest-block-retry-interval")),
		)

		httpClient, err := http.New(ctx,
			http.WithAddress(httpEndpoint),
			http.WithLogLevel(zerolog.Disabled),
			http.WithTimeout(sflags.MustGetDuration(cmd, "http-timeout")),
		)
		if err != nil {
			return fmt.Errorf("failed to create Lighthouse http client: %w", err)
		}

		latestBlockRetryInterval := sflags.MustGetDuration(cmd, "latest-block-retry-interval")
		httpFetcher, err := blockfetcher.NewHttp(httpClient, fetchInterval, latestBlockRetryInterval, logger)
		if err != nil {
			return fmt.Errorf("failed to setup http blockfetcher: %w", err)
		}

		poller := blockpoller.New(
			httpFetcher,
			blockpoller.NewFireBlockHandler("type.googleapis.com/sf.beacon.type.v1.Block"),
			blockpoller.WithStoringState(stateDir),
			blockpoller.WithLogger(logger),
		)

		err = poller.Run(ctx, startBlock, sflags.MustGetInt(cmd, "block-fetch-batch-size"))
		if err != nil {
			return fmt.Errorf("running poller: %w", err)
		}

		return nil
	}
}
