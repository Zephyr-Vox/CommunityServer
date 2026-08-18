package protocol

// ReplayWindow is a 128-packet sliding receive window: one 64-bit high-water
// mark plus a 128-bit bitmap for the 127 slots below it (the high-water mark
// itself is represented by bitmap bit 0).
//
// The window is deliberately small and deterministic:
//   - one 20ms stream  -> 50 pps  -> 128 packets cover ~2.56s;
//   - one 10ms stream  -> 100 pps -> 128 packets cover ~1.28s;
//   - two 10ms streams -> 200 pps -> 128 packets cover ~0.64s;
//   - the 300 pps session cap -> 128 packets cover ~0.43s.
//
// Change this constant only with that arithmetic in mind.
const replayWindowSize = 128

// ReplayWindow is not internally synchronized: each session guards its rx
// window with Session.mu, and the UDP hot path only touches it inside that
// lock.
type ReplayWindow struct {
	high uint64
	bits [2]uint64
}

// WouldAccept reports whether Accept would admit seq without changing window
// state. The caller holds the same Session mutex used for Accept.
func (w *ReplayWindow) WouldAccept(seq uint64) bool {
	if seq == 0 {
		return false
	}
	if seq > w.high {
		return true
	}
	offset := w.high - seq
	if offset >= replayWindowSize {
		return false
	}
	word := offset / 64
	bit := uint(offset % 64)
	return w.bits[word]&(uint64(1)<<bit) == 0
}

// Accept classifies one received sequence number.
//
// accepted = the packet is not a replay and is inside the window
// advanced = the high-water mark moved forward
//
// seq 0 is always rejected. Sequence numbers are 64-bit and will never wrap
// in practice; when high is near math.MaxUint64 a small seq naturally falls
// out of the window and is rejected. No wraparound logic exists on purpose.
func (w *ReplayWindow) Accept(seq uint64) (accepted bool, advanced bool) {
	if seq == 0 {
		return false, false
	}

	if seq > w.high {
		delta := seq - w.high
		if delta >= replayWindowSize {
			// The sender jumped beyond the whole window: old state is
			// useless, but this fresh seq is accepted.
			w.bits = [2]uint64{}
		} else {
			w.shiftLeft(uint(delta))
		}
		w.high = seq
		w.bits[0] |= 1 // bit 0 represents high itself
		return true, true
	}

	// seq <= high, so high-seq cannot underflow.
	offset := w.high - seq
	if offset >= replayWindowSize {
		return false, false
	}
	word := offset / 64
	bit := uint(offset % 64)
	mask := uint64(1) << bit
	if w.bits[word]&mask != 0 {
		return false, false
	}
	w.bits[word] |= mask
	return true, false
}

// shiftLeft shifts the 128-bit bitmap left by n (0..127), dropping the oldest
// bits. bit 0 is the newest sequence (high) and bit 127 is the oldest.
func (w *ReplayWindow) shiftLeft(n uint) {
	switch {
	case n == 0:
		return
	case n < 64:
		w.bits[1] = (w.bits[1] << n) | (w.bits[0] >> (64 - n))
		w.bits[0] <<= n
	default:
		// 64..127: only bits[0] can survive, shifted into bits[1].
		w.bits[1] = w.bits[0] << (n - 64)
		w.bits[0] = 0
	}
}
