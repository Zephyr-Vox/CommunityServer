package protocol_test

import (
	"errors"
	"sync"
	"testing"

	"zephyr.vox/server/ce/internal/protocol"
)

func TestChannelRegistryRegisterAndLookup(t *testing.T) {
	r := protocol.NewChannelTypeRegistry()
	if err := r.Register(1, protocol.Capabilities{Name: "mic"}); err != nil {
		t.Fatal(err)
	}
	if err := r.Register(2, protocol.Capabilities{Name: "desktop_audio", Fragmentable: true}); err != nil {
		t.Fatal(err)
	}
	if !r.Registered(1) || !r.Registered(2) {
		t.Fatal("registered channels not visible")
	}
	if r.Registered(0) || r.Registered(3) {
		t.Fatal("heartbeat or unknown channel reported as registered")
	}
	caps, ok := r.Lookup(2)
	if !ok || caps.Name != "desktop_audio" || !caps.Fragmentable {
		t.Fatalf("lookup = (%+v,%v)", caps, ok)
	}
}

func TestChannelRegistryRejectsHeartbeatAndDuplicates(t *testing.T) {
	r := protocol.NewChannelTypeRegistry()
	if err := r.Register(0, protocol.Capabilities{Name: "heartbeat"}); !errors.Is(err, protocol.ErrChannelTypeReserved) {
		t.Fatalf("type 0 err = %v, want ErrChannelTypeReserved", err)
	}
	if err := r.Register(1, protocol.Capabilities{Name: "mic"}); err != nil {
		t.Fatal(err)
	}
	if err := r.Register(1, protocol.Capabilities{Name: "mic again"}); !errors.Is(err, protocol.ErrChannelAlreadyRegistered) {
		t.Fatalf("duplicate err = %v, want ErrChannelAlreadyRegistered", err)
	}
}

func TestChannelRegistrySealedRejectsRegister(t *testing.T) {
	r := protocol.NewChannelTypeRegistry()
	if err := r.Register(1, protocol.Capabilities{Name: "mic"}); err != nil {
		t.Fatal(err)
	}
	r.Seal()
	if err := r.Register(2, protocol.Capabilities{Name: "late"}); !errors.Is(err, protocol.ErrChannelRegistrySealed) {
		t.Fatalf("late register err = %v, want ErrChannelRegistrySealed", err)
	}
	if !r.Registered(1) {
		t.Fatal("sealed registry must keep serving reads")
	}
}

func TestChannelRegistryConcurrentRegisterAndRead(t *testing.T) {
	r := protocol.NewChannelTypeRegistry()
	var wg sync.WaitGroup
	for i := range 8 {
		id := uint8(i + 1)
		wg.Go(func() {
			_ = r.Register(id%8+1, protocol.Capabilities{Name: "stream"})
		})
	}
	for range 8 {
		wg.Go(func() {
			for j := range 100 {
				_, _ = r.Lookup(uint8(j%8 + 1))
			}
		})
	}
	wg.Wait()
	for i := range 8 {
		if !r.Registered(uint8(i + 1)) {
			t.Fatalf("channel %d missing after concurrent registration", i+1)
		}
	}
}
