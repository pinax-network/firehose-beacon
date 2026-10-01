# Firehose on Beacon

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

This is the poller implementation to create Firehose blocks from Beacon chains. It enables both 
[Firehose](https://firehose.streamingfast.io/introduction/firehose-overview)
and [Substreams](https://substreams.streamingfast.io) on Beacon chains. It supports all current specs (Phase0, Altair, Bellatrix, Capella, Deneb, 
Electra, Fusaka and Gloas). 
Since the Deneb spec, we embed blobs into the firehose blocks.

Since the Gloas spec (EIP-7732, ePBS), the execution payload is no longer part of the beacon block. The poller stays one
slot behind the head and embeds the payload envelope and blobs only if the next block built on top of it. Because the next
block can still be reorged, the Firehose block ID of a Gloas block encodes the payload status: it equals the beacon
block root if the payload was included, and is a hash derived from the root otherwise. A change of the payload status
is thereby handled like any other fork.

The block proto can be found [here](https://github.com/pinax-network/firehose-beacon/blob/main/proto/sf/beacon/type/v1/type.proto).

**Note** this is still work in progress and the block type might change, nor do we have extensive
testing and data validation yet.
