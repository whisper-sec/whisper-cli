// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

// Package observed is the on-disk shape of the rollup the host sensor publishes and
// the panel reads. It is a file format, nothing more: four counters and their
// per-minute history.
//
// It lives here rather than beside the sensor because the two ends of this contract
// sit on opposite sides of a boundary. The sensor is a closed component; the panel
// ships in the open client. A reader has to agree with a writer about field names to
// unmarshal anything at all, so the writer's package is the wrong place to keep the
// agreement - the reader would have to import the sensor to read a JSON file, and a
// client that imports the sensor is a client that cannot be published without it.
//
// Nothing about detection is described here. What events mean, how they are decided,
// and what is done about them stay where they belong. This says only that a document
// with these field names exists and how to read one.
package observed

// Counts is one bucket, and the same shape is reused for the totals.
type Counts struct {
	Exec uint64 `json:"exec"`
	File uint64 `json:"file"`
	Conn uint64 `json:"conn"`
	DNS  uint64 `json:"dns"`
}

// Snapshot is the document written to disk.
type Snapshot struct {
	Schema        int    `json:"schema"`
	UpdatedAt     string `json:"updated_at"`
	Since         string `json:"since"`
	BucketSeconds int    `json:"bucket_seconds"`
	// Series are aligned oldest-first. The last entry is the bucket containing
	// UpdatedAt, so a reader can walk backwards from "now" without trusting its own
	// clock against the writer's.
	Series map[string][]uint64 `json:"series"`
	Totals Counts              `json:"totals"`
}
