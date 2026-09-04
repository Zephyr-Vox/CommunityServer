package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"

	"zephyr.vox/server/ce/internal/protocol"
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
	errCh, err := v.server.Start(packetConn)
	if err != nil {
		v.closeMu.Unlock()
		return fmt.Errorf("server: start voice: %w", err)
	}
	v.stopPurge = v.server.StartPurge(protocol.PurgeInterval)
	v.fatal = supervisor.Fatal
	v.started = true
	v.closeMu.Unlock()

	// UDPServer owns PacketConn after Start. Its non-close return is fatal; the
	// supervisor cancels the process root and owns the subsequent stop sequence.
	supervisor.Go("udp read", func(context.Context) error { return <-errCh })
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
	return nil
}

// Close stops purge production before closing the UDP listener, then waits for
// the read loop through UDPServer.Close. It is idempotent and safe after a
// failed partial startup.
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
		v.closeErr = v.server.Close()
	})
	return v.closeErr
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
