// Package relay implements the bounded voice media data plane.
package relay

import (
	"context"
	"sync"
)

const (
	// ShardCount is the fixed number of independent relay queue shards.
	ShardCount = 8
	// MaxQueueItems is the process-wide item cap across all relay shards.
	MaxQueueItems = 4096
	// MaxQueueBytes is the process-wide payload cap across all relay shards.
	MaxQueueBytes = 16 << 20
	// MaxShardItems is the per-shard item cap. It prevents one hot speaker from
	// consuming the entire process-wide queue budget.
	MaxShardItems = MaxQueueItems / ShardCount
	// MaxShardBytes is the per-shard payload cap.
	MaxShardBytes = MaxQueueBytes / ShardCount
)

// Frame is the owned copy of one validated inbound media frame. Queue
// admission copies Payload because protocol.InboundFrame aliases the UDP read
// buffer and is valid only during the protocol callback.
type Frame struct {
	Source       Source
	ChannelType  uint8
	ChannelSeq   uint16
	TransportSeq uint64
	Payload      []byte
}

// QueueStats is a coherent queue occupancy snapshot.
type QueueStats struct {
	Items            int                 `json:"items"`
	Bytes            int                 `json:"bytes"`
	ItemCapacity     int                 `json:"item_capacity"`
	ByteCapacity     int                 `json:"byte_capacity"`
	Utilization      float64             `json:"utilization"`
	ShardItems       [ShardCount]int     `json:"shard_items"`
	ShardBytes       [ShardCount]int     `json:"shard_bytes"`
	ShardUtilization [ShardCount]float64 `json:"shard_utilization"`
}

// Queue is a fixed eight-shard queue with both item and byte bounds. Admission
// and removal use the same lock order (global admission lock, then shard
// lock), so the process-wide cap remains exact under concurrent producers and
// workers. Enqueue never waits for a consumer.
type Queue struct {
	shards [ShardCount]*queueShard

	admissionMu sync.Mutex
	items       int
	bytes       int
	closed      bool
}

type queueShard struct {
	mu     sync.Mutex
	items  int
	bytes  int
	queue  []Frame
	ready  chan struct{}
	closed bool
}

// NewQueue constructs an empty fixed-capacity relay queue.
func NewQueue() *Queue {
	q := &Queue{}
	for index := range q.shards {
		q.shards[index] = &queueShard{ready: make(chan struct{}, 1), queue: make([]Frame, 0, MaxShardItems)}
	}
	return q
}

// ShardFor returns the stable shard selected by a source user and channel type.
// A source/channel pair therefore retains FIFO order while unrelated streams
// can be consumed by other workers.
func ShardFor(userID int64, channelType uint8) int {
	value := uint64(userID) ^ (uint64(channelType) * 0x9e3779b97f4a7c15)
	value ^= value >> 30
	value *= 0xbf58476d1ce4e5b9
	value ^= value >> 27
	value *= 0x94d049bb133111eb
	value ^= value >> 31
	return int(value % ShardCount)
}

// Enqueue admits one frame if every fixed item and byte budget remains. It
// returns false for overload or closure; the caller owns the corresponding
// drop accounting and must not retry synchronously.
func (q *Queue) Enqueue(shard int, frame Frame) bool {
	if q == nil || shard < 0 || shard >= ShardCount || frame.Source.UserID <= 0 || len(frame.Payload) == 0 {
		return false
	}
	if len(frame.Payload) > MaxShardBytes || len(frame.Payload) > MaxQueueBytes {
		return false
	}
	owned := cloneFrame(frame)
	q.admissionMu.Lock()
	defer q.admissionMu.Unlock()
	if q.closed || q.items >= MaxQueueItems || q.bytes+len(owned.Payload) > MaxQueueBytes {
		return false
	}
	item := q.shards[shard]
	item.mu.Lock()
	defer item.mu.Unlock()
	if item.closed || item.items >= MaxShardItems || item.bytes+len(owned.Payload) > MaxShardBytes {
		return false
	}
	item.queue = append(item.queue, owned)
	item.items++
	item.bytes += len(owned.Payload)
	q.items++
	q.bytes += len(owned.Payload)
	item.signalLocked()
	return true
}

// Pop waits for and removes the oldest frame from shard. The returned frame's
// payload remains owned by the caller and is not reused by Queue.
func (q *Queue) Pop(ctx context.Context, shard int) (Frame, bool) {
	if q == nil || ctx == nil || shard < 0 || shard >= ShardCount {
		return Frame{}, false
	}
	item := q.shards[shard]
	for {
		q.admissionMu.Lock()
		item.mu.Lock()
		if len(item.queue) != 0 {
			frame := item.queue[0]
			item.queue[0] = Frame{}
			item.queue = item.queue[1:]
			item.items--
			item.bytes -= len(frame.Payload)
			if len(item.queue) != 0 {
				item.signalLocked()
			}
			q.items--
			q.bytes -= len(frame.Payload)
			q.admissionMu.Unlock()
			item.mu.Unlock()
			return frame, true
		}
		closed := item.closed
		ready := item.ready
		item.mu.Unlock()
		q.admissionMu.Unlock()
		if closed {
			return Frame{}, false
		}
		select {
		case <-ready:
		case <-ctx.Done():
			return Frame{}, false
		}
	}
}

// Close rejects new frames and discards every frame still waiting in every
// shard. It is idempotent and never waits for workers.
func (q *Queue) Close() {
	if q == nil {
		return
	}
	q.admissionMu.Lock()
	if q.closed {
		q.admissionMu.Unlock()
		return
	}
	q.closed = true
	q.items = 0
	q.bytes = 0
	for _, item := range q.shards {
		item.mu.Lock()
		item.closed = true
		item.items = 0
		item.bytes = 0
		clear(item.queue)
		item.queue = nil
		item.signalLocked()
		item.mu.Unlock()
	}
	q.admissionMu.Unlock()
}

// Stats returns a bounded occupancy snapshot without exposing mutable queue
// storage. It is intended for metrics and load-control sampling.
func (q *Queue) Stats() QueueStats {
	if q == nil {
		return QueueStats{}
	}
	q.admissionMu.Lock()
	defer q.admissionMu.Unlock()
	items, bytes, closed := q.items, q.bytes, q.closed
	stats := QueueStats{Items: items, Bytes: bytes, ItemCapacity: MaxQueueItems, ByteCapacity: MaxQueueBytes}
	if closed {
		return stats
	}
	stats.Utilization = maxRatio(float64(items)/MaxQueueItems, float64(bytes)/MaxQueueBytes)
	for index, item := range q.shards {
		item.mu.Lock()
		stats.ShardItems[index] = item.items
		stats.ShardBytes[index] = item.bytes
		item.mu.Unlock()
		stats.ShardUtilization[index] = maxRatio(float64(stats.ShardItems[index])/MaxShardItems, float64(stats.ShardBytes[index])/MaxShardBytes)
	}
	return stats
}

// cloneFrame creates the queue-owned payload copy and preserves every source
// sequence and generation field without renumbering the media stream.
func cloneFrame(frame Frame) Frame {
	frame.Payload = append([]byte(nil), frame.Payload...)
	return frame
}

// signalLocked wakes at least one worker for a non-empty or closed shard.
func (s *queueShard) signalLocked() {
	select {
	case s.ready <- struct{}{}:
	default:
	}
}

// maxRatio returns the larger of two utilization ratios.
func maxRatio(left, right float64) float64 {
	if left > right {
		return left
	}
	return right
}
