# Firehose on Beacon

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

This is the poller implementation to create Firehose blocks from Beacon chains. It enables both 
[Firehose](https://firehose.streamingfast.io/introduction/firehose-overview)
and [Substreams](https://substreams.streamingfast.io) on Beacon chains. It supports all current specs (Phase0, Altair, Bellatrix, Capella and Deneb). 
For the Deneb spec we embed blobs into the firehose blocks.

The block proto can be found [here](https://github.com/pinax-network/firehose-beacon/blob/main/proto/sf/beacon/type/v1/type.proto).

**Note** this is still work in progress and the block type might change, nor do we have extensive
testing and data validation yet.
