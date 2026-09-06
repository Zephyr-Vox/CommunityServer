package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"

	"zephyr.vox/server/ce/internal/protocol"
	"zephyr.vox/server/ce/internal/relay"
)

// Start binds the process-wide UDP listener and registers its read loop and
// purge worker with supervisor. It must run before readiness is published; a
// UDP bind or read-loop failure is process-fatal rather than a degraded
// HTTP-only mode.
func (v *voiceRuntime) Start(ctx context.Context, host string, port int, supervisor *ProcessSupervisor) error {
	if v == nil || v.server == nil || supervisor == nil || host == "" || port < 1 || port > 65535 {
		return errors.New("server: invalid voice runtime startup")
	}
	v.closeMu.Lock()
	if v.started {
		v.closeMu.Unlock()
		return errors.New("server: voice runtime already started")
	}
	if v.closed {
		v.closeMu.Unlock()
		return errors.New("server: voice runtime already closed")
	}
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		v.closeMu.Unlock()
		return fmt.Errorf("server: resolve voice listener: %w", err)
	}
	packetConn, err := net.ListenUDP("udp", addr)
	if err != nil {
		v.closeMu.Unlock()
		return fmt.Errorf("server: listen voice %s: %w", addr, err)
	}
	var relayDone <-chan error
	if v.relay != nil {
		relayDone, err = v.relay.Start(supervisor.Context())
		if err != nil {
			_ = packetConn.Close()
			v.closeMu.Unlock()
			return fmt.Errorf("server: start voice relay: %w", err)
		}
	}
	errCh, err := v.server.Start(packetConn)
	if err != nil {
		if v.relay != nil {
			_ = v.relay.Close(context.Background())
		}
		v.closeMu.Unlock()
		return fmt.Errorf("server: start voice: %w", err)
	}
	purgeCtx, purgeCancel := context.WithCancel(supervisor.Context())
	purgeDone := make(chan struct{})
	v.stopPurge = func() {
		purgeCancel()
		<-purgeDone
	}
	v.fatal = supervisor.Fatal
	v.started = true

	// UDPServer owns PacketConn after Start. Its non-close return is fatal; the
	// supervisor cancels the process root and owns the subsequent stop sequence.
	// Keep closeMu held until all stopPurge dependencies are registered: a
	// concurrent App.Close must not wait on purgeDone before its worker exists.
	supervisor.Go("udp read", func(context.Context) error { return <-errCh })
	if relayDone != nil {
		supervisor.Go("voice relay", func(ctx context.Context) error {
			select {
			case err, ok := <-relayDone:
				if !ok || ctx.Err() != nil {
					return nil
				}
				return err
			case <-ctx.Done():
				return nil
			}
		})
	}
	if v.load != nil && v.loadInput != nil {
		supervisor.Go("voice load controller", func(ctx context.Context) error {
			return v.load.Run(ctx, v.loadInput)
		})
	}
	if v.diagnostics != nil {
		supervisor.Go("voice stats", v.runVoiceStats)
	}
	supervisor.Go("udp purge", func(context.Context) error {
		defer close(purgeDone)
		return v.server.RunPurge(purgeCtx, protocol.PurgeInterval)
	})
	supervisor.Go("udp revocation", func(ctx context.Context) error {
		for {
			select {
			case cleanup := <-v.revocations:
				if cleanup != nil {
					cleanup()
				}
			case <-ctx.Done():
				return nil
			}
		}
	})
	supervisor.Go("udp expiry cleanup", func(ctx context.Context) error {
		for {
			select {
			case expiry := <-v.expiries:
				if expiry.drain != nil {
					expiry.drain()
				}
				authority, ok := v.connections.VoiceAuthority(expiry.userID)
				if !ok || authority.VoiceSessionID != expiry.sessionID {
					continue
				}
				if _, _, err := v.connections.BeginVoiceDisconnectReason(authority, nil, "udp_timeout"); err != nil {
					return err
				}
			case <-ctx.Done():
				return nil
			}
		}
	})
	v.closeMu.Unlock()
	return nil
}

// Close stops purge production, closes the UDP listener, and then waits for the
// relay workers. Closing the listener before waiting for relay workers unblocks
// any in-flight UDP write. It is idempotent and safe after a failed partial
// startup.
func (v *voiceRuntime) Close() error {
	if v == nil || v.server == nil {
		return nil
	}
	v.closeOnce.Do(func() {
		v.closeMu.Lock()
		v.closed = true
		stopPurge := v.stopPurge
		v.stopPurge = nil
		v.closeMu.Unlock()
		if stopPurge != nil {
			stopPurge()
		}
		serverErr := v.server.Close()
		relayErr := v.stopRelay(context.Background())
		v.closeErr = errors.Join(serverErr, relayErr)
	})
	return v.closeErr
}

// stopRelay closes the bounded media queue and waits for all fanout workers.
// It is separate from UDPServer.Close so callers can stop new media work after
// the socket is closed and in-flight UDP writes have been unblocked.
func (v *voiceRuntime) stopRelay(ctx context.Context) error {
	if v == nil || v.relay == nil {
		return nil
	}
	err := v.relay.Close(ctx)
	if errors.Is(err, relay.ErrRelayNotStarted) {
		return nil
	}
	return err
}

// Manager returns the voice session registry for staged authority commands.
// It intentionally exposes protocol's narrow manager API rather than UDPServer
// internals, keeping control-plane ownership outside the transport package.
func (v *voiceRuntime) Manager() *protocol.Manager {
	if v == nil {
		return nil
	}
	return v.manager
}
