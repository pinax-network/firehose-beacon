package http

import (
	"fmt"
	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/http"
	"github.com/pinax-network/firehose-beacon/blockfetcher"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"github.com/streamingfast/cli/sflags"
	firecore "github.com/streamingfast/firehose-core"
	"github.com/streamingfast/firehose-core/blockpoller"
	"github.com/streamingfast/firehose-core/rpc"
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
	cmd.Flags().Duration("max-block-fetch-duration", 5*time.Second, "maximum delay before retrying a block fetch")
	cmd.Flags().Bool("ignore-missing-blobs", false, "ignores missing blob data for a slot which is probably caused due to Lighthouse having pruned them")

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
		maxBlockFetchDuration := sflags.MustGetDuration(cmd, "max-block-fetch-duration")
		latestBlockRetryInterval := sflags.MustGetDuration(cmd, "latest-block-retry-interval")

		logger.Info(
			"launching firehose-beacon poller",
			zap.String("http_endpoint", httpEndpoint),
			zap.String("state_dir", stateDir),
			zap.Uint64("first_streamable_block", startBlock),
			zap.Duration("interval_between_fetch", fetchInterval),
			zap.Duration("max_block_fetch_duration", maxBlockFetchDuration),
			zap.Duration("latest_block_retry_interval", latestBlockRetryInterval),
		)

		logLevel := zerolog.WarnLevel
		if tracer.Enabled() {
			logLevel = zerolog.DebugLevel
		}

		httpClient, err := http.New(ctx,
			http.WithAddress(httpEndpoint),
			http.WithLogLevel(logLevel),
			http.WithTimeout(maxBlockFetchDuration),
		)
		if err != nil {
			return fmt.Errorf("failed to create Lighthouse http client: %w", err)
		}

		httpFetcher, err := blockfetcher.NewHttp(httpClient, fetchInterval, latestBlockRetryInterval, sflags.MustGetBool(cmd, "ignore-missing-blobs"), logger)
		if err != nil {
			return fmt.Errorf("failed to setup http blockfetcher: %w", err)
		}

		rpcClients := rpc.NewClients(maxBlockFetchDuration, rpc.NewStickyRollingStrategy[eth2client.Service](), logger)
		rpcClients.Add(httpClient)

		handler := blockpoller.NewFireBlockHandler("type.googleapis.com/sf.beacon.type.v1.Block")
		poller := blockpoller.New[eth2client.Service](httpFetcher, handler, rpcClients, blockpoller.WithStoringState[eth2client.Service](stateDir), blockpoller.WithLogger[eth2client.Service](logger))

		err = poller.Run(startBlock, nil, sflags.MustGetInt(cmd, "block-fetch-batch-size"))
		if err != nil {
			return fmt.Errorf("running poller: %w", err)
		}

		return nil
	}
}
