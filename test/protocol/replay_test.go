package protocol_test

import (
	"math"
	"testing"

	"zephyr.vox/server/ce/internal/protocol"
)

func TestReplayWindowInitialState(t *testing.T) {
	var w protocol.ReplayWindow
	accepted, advanced := w.Accept(1)
	if !accepted || !advanced {
		t.Fatalf("seq=1 = (%v,%v), want (true,true)", accepted, advanced)
	}
	if accepted, _ = w.Accept(0); accepted {
		t.Fatal("seq=0 must always be rejected")
	}
}

func TestReplayWindowSequentialAndDuplicate(t *testing.T) {
	var w protocol.ReplayWindow
	for i := range 10 {
		seq := uint64(i + 1)
		if accepted, advanced := w.Accept(seq); !accepted || !advanced {
			t.Fatalf("seq=%d = (%v,%v), want accepted+advanced", seq, accepted, advanced)
		}
	}
	for i := range 10 {
		seq := uint64(i + 1)
		if accepted, advanced := w.Accept(seq); accepted || advanced {
			t.Fatalf("duplicate seq=%d = (%v,%v), want rejected", seq, accepted, advanced)
		}
	}
}

func TestReplayWindowInWindowOutOfOrder(t *testing.T) {
	var w protocol.ReplayWindow
	w.Accept(1)
	w.Accept(2)
	w.Accept(3)

	if accepted, _ := w.Accept(2); accepted {
		t.Fatal("duplicate in-window seq accepted")
	}
	if accepted, advanced := w.Accept(10); !accepted || !advanced {
		t.Fatalf("seq=10 = (%v,%v)", accepted, advanced)
	}
	accepted, advanced := w.Accept(9)
	if !accepted || advanced {
		t.Fatalf("seq=9 = (%v,%v), want (true,false)", accepted, advanced)
	}
}

func TestReplayWindowOldSequenceRejected(t *testing.T) {
	var w protocol.ReplayWindow
	for i := range 200 {
		w.Accept(uint64(i + 1))
	}
	if accepted, _ := w.Accept(72); accepted {
		t.Fatal("seq older than 128 packets accepted")
	}
	if accepted, _ := w.Accept(71); accepted {
		t.Fatal("seq outside the 128-packet window accepted")
	}
}

func TestReplayWindowWouldAcceptIsNonMutatingAtBoundary(t *testing.T) {
	var w protocol.ReplayWindow
	if accepted, advanced := w.Accept(200); !accepted || !advanced {
		t.Fatalf("initial high = (%v,%v)", accepted, advanced)
	}
	if !w.WouldAccept(73) || !w.WouldAccept(73) {
		t.Fatal("offset 127 must be accepted without mutation")
	}
	if accepted, advanced := w.Accept(73); !accepted || advanced {
		t.Fatalf("Accept(73) = (%v,%v), want (true,false)", accepted, advanced)
	}
	if w.WouldAccept(73) {
		t.Fatal("WouldAccept accepted a sequence committed by Accept")
	}
	if w.WouldAccept(72) {
		t.Fatal("offset 128 must be outside the replay window")
	}
	if w.WouldAccept(0) {
		t.Fatal("WouldAccept accepted sequence zero")
	}
}

func TestReplayWindowJumpClearsWindow(t *testing.T) {
	var w protocol.ReplayWindow
	w.Accept(1)
	w.Accept(2)
	accepted, advanced := w.Accept(500)
	if !accepted || !advanced {
		t.Fatalf("jump = (%v,%v), want (true,true)", accepted, advanced)
	}
	if accepted, _ := w.Accept(2); accepted {
		t.Fatal("seq cleared by a forward jump was accepted")
	}
}

func TestReplayWindowNearMaxUint64RejectsSmallSequence(t *testing.T) {
	var w protocol.ReplayWindow
	accepted, advanced := w.Accept(math.MaxUint64 - 10)
	if !accepted || !advanced {
		t.Fatal("near-max sequence rejected")
	}
	if accepted, _ := w.Accept(7); accepted {
		t.Fatal("small seq accepted when high is near MaxUint64")
	}
	if accepted, _ := w.Accept(0); accepted {
		t.Fatal("seq=0 accepted when high is near MaxUint64")
	}
}

func TestReplayWindowShiftAcrossWords(t *testing.T) {
	var w protocol.ReplayWindow
	w.Accept(1)
	w.Accept(71)
	if accepted, _ := w.Accept(1); accepted {
		t.Fatal("seen seq replayed across word boundary accepted")
	}
	accepted, advanced := w.Accept(2)
	if !accepted || advanced {
		t.Fatalf("seq=2 = (%v,%v), want (true,false)", accepted, advanced)
	}
}
