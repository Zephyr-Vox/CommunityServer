package channel

import "zephyr.vox/server/ce/internal/realtime"

// groupPageResponse is one visible page of canonical group snapshots.
type groupPageResponse struct {
	Items  []realtime.SnapshotGroup `json:"items"`
	Limit  int64                    `json:"limit"`
	Offset int64                    `json:"offset"`
	Total  int64                    `json:"total"`
}

// channelPageResponse is one visible page of canonical channel snapshots.
type channelPageResponse struct {
	Items  []realtime.SnapshotChannel `json:"items"`
	Limit  int64                      `json:"limit"`
	Offset int64                      `json:"offset"`
	Total  int64                      `json:"total"`
}
