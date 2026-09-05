package relay_test

import (
	"testing"
	"time"

	"zephyr.vox/server/ce/internal/relay"
)

func TestLoadControllerStepsDownAndRecoversSlowly(t *testing.T) {
	controller, err := relay.NewLoadController(relay.HardLimits{GlobalPacketsPerSec: 1000, SessionPacketsPerSec: 300}, nil)
	if err != nil {
		t.Fatal(err)
	}
	limits := controller.Tick(relay.LoadInput{QueueUtilization: 0.9})
	if limits.GlobalPacketsPerSec != 800 || limits.SessionPacketsPerSec != 240 || limits.VoiceStatsInterval != 10*time.Second {
		t.Fatalf("overload limits = %+v", limits)
	}
	for tick := 0; tick < relay.LoadRecoveryTicks*10; tick++ {
		limits = controller.Tick(relay.LoadInput{})
	}
	if limits.GlobalPacketsPerSec > 1000 || limits.SessionPacketsPerSec > 300 || limits.VoiceStatsInterval < 5*time.Second {
		t.Fatalf("recovered beyond hard limits = %+v", limits)
	}
	if limits.GlobalPacketsPerSec != 1000 || limits.SessionPacketsPerSec != 300 || limits.VoiceStatsInterval != 5*time.Second {
		t.Fatalf("did not recover after clean ticks = %+v", limits)
	}
}

func TestLoadControllerHonorsConfiguredLowerBounds(t *testing.T) {
	controller, err := relay.NewLoadController(relay.HardLimits{GlobalPacketsPerSec: 8, SessionPacketsPerSec: 200}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var limits relay.SoftLimits
	for tick := 0; tick < 40; tick++ {
		limits = controller.Tick(relay.LoadInput{RelayDropRatio: 0.05})
	}
	if limits.GlobalPacketsPerSec != 2 {
		t.Fatalf("global lower bound = %d, want 2", limits.GlobalPacketsPerSec)
	}
	if limits.SessionPacketsPerSec != 50 {
		t.Fatalf("session lower bound = %d, want 50", limits.SessionPacketsPerSec)
	}

	controller, err = relay.NewLoadController(relay.HardLimits{GlobalPacketsPerSec: 8, SessionPacketsPerSec: 30}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for tick := 0; tick < 40; tick++ {
		limits = controller.Tick(relay.LoadInput{QueueUtilization: 0.9})
	}
	if limits.SessionPacketsPerSec != 30 {
		t.Fatalf("custom session hard cap = %d, want 30", limits.SessionPacketsPerSec)
	}
}
