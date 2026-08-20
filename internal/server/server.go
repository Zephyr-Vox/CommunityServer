package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"time"

	"zephyr.vox/server/ce/internal/cert"
	"zephyr.vox/server/ce/internal/config"
	"zephyr.vox/server/ce/internal/servercard"
)

// shutdownTimeout is how long Run waits for in-flight requests to drain after
// the context is cancelled.
const shutdownTimeout = 10 * time.Second

const (
	defaultReadHeaderTimeout = 10 * time.Second
	defaultReadTimeout       = 60 * time.Second
	defaultWriteTimeout      = 120 * time.Second
	defaultIdleTimeout       = 60 * time.Second
)

// HTTPTimeouts bounds the lifetime of ordinary HTTP requests and idle
// connections. All fields must be positive when supplied through RunOptions.
type HTTPTimeouts struct {
	ReadHeader time.Duration
	Read       time.Duration
	Write      time.Duration
	Idle       time.Duration
}

// DefaultHTTPTimeouts returns the fixed production HTTP deadline policy.
func DefaultHTTPTimeouts() HTTPTimeouts {
	return HTTPTimeouts{
		ReadHeader: defaultReadHeaderTimeout,
		Read:       defaultReadTimeout,
		Write:      defaultWriteTimeout,
		Idle:       defaultIdleTimeout,
	}
}

// RunOptions carries per-invocation startup switches that are not part of the
// persisted configuration. Keeping them out of ServerConfig makes it obvious
// that flags like -force-regenerate-cert are one-shot operator actions.
type RunOptions struct {
	ForceRegenerateCert bool
	HTTPTimeouts        *HTTPTimeouts
}

// Run listens on cfg.Server.Host:HTTPPort and serves until ctx is cancelled,
// then shuts the server down gracefully and returns. The TLS mode comes from
// cfg.Server.TLSMode; an empty value fails closed to required so a directly
// constructed App cannot silently fall back to plaintext.
func (a *App) Run(ctx context.Context, opts ...RunOptions) error {
	var runOpts RunOptions
	if len(opts) > 0 {
		runOpts = opts[0]
	}
	timeouts := DefaultHTTPTimeouts()
	if runOpts.HTTPTimeouts != nil {
		timeouts = *runOpts.HTTPTimeouts
		if err := timeouts.validate(); err != nil {
			return err
		}
	}
	running, err := a.beginRun(ctx)
	if err != nil {
		return err
	}
	defer a.finishRun(running)

	addr := net.JoinHostPort(a.cfg.Server.Host, strconv.Itoa(a.cfg.Server.HTTPPort))

	// Bind before claiming readiness: a goroutine-based ListenAndServe would
	// hide a bind failure, letting "http listening"/"LINK START" print even
	// though the process is about to exit with an error.
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("server: listen %s: %w", addr, err)
	}

	mode := a.cfg.Server.TLSMode
	if mode == "" {
		mode = config.TLSModeRequired
	}
	var tlsInfo func()
	switch mode {
	case config.TLSModeOff:
		// Plaintext only: no certificate is loaded or generated.
		if runOpts.ForceRegenerateCert {
			ln.Close()
			return errors.New("server: -force-regenerate-cert requires tls_mode required")
		}
	case config.TLSModeRequired:
		bundle, err := cert.LoadOrCreate(cert.Config{
			StorePath:  a.cfg.Server.TLSCertPath,
			CertFile:   a.cfg.Server.TLSCert,
			KeyFile:    a.cfg.Server.TLSKey,
			ValidYears: a.cfg.Server.TLSCertValidYears,
			ExtraSANs:  a.cfg.Server.TLSCertExtraSANs,
		}, runOpts.ForceRegenerateCert, time.Now())
		if err != nil {
			ln.Close()
			return fmt.Errorf("server: load certificate: %w", err)
		}
		tlsCfg := &tls.Config{
			MinVersion:   tls.VersionTLS12,
			NextProtos:   []string{"h2", "http/1.1"},
			Certificates: []tls.Certificate{bundle.Certificate},
		}
		ln = tls.NewListener(ln, tlsCfg)
		joinURL := ""
		if !isWildcardHost(a.cfg.Server.Host) {
			card, err := servercard.New(a.cfg.Server.Host, a.cfg.Server.HTTPPort, bundle.Fingerprint, "", true)
			if err != nil {
				ln.Close()
				return fmt.Errorf("server: build join url: %w", err)
			}
			joinURL = card.String()
		}
		tlsInfo = func() {
			tlsLog := a.logger.With("module", "tls")
			switch bundle.Action {
			case cert.ActionGenerated:
				tlsLog.Info("self-signed certificate generated", "cert", bundle.CertFile)
			case cert.ActionRenewed:
				tlsLog.Info("certificate renewed, fingerprint unchanged")
			case cert.ActionReissued:
				tlsLog.Info("certificate reissued, fingerprint unchanged")
			case cert.ActionReused:
				tlsLog.Info("using existing certificate")
			case cert.ActionRegenerated:
				// A new private key means a new fingerprint: every already
				// pinned client will reject the server until it receives a
				// new join URL, so this must be a WARN, not an INFO.
				if bundle.BackupDir != "" {
					tlsLog.Warn("private key regenerated; fingerprint changed", "backup", bundle.BackupDir)
				} else {
					tlsLog.Warn("private key regenerated; fingerprint changed")
				}
			}
			tlsLog.Info("tls fingerprint: " + bundle.Fingerprint)
			if joinURL != "" {
				tlsLog.Info("join url: " + joinURL)
			} else {
				tlsLog.Warn("join url unavailable: server.host is a wildcard listen address; configure a reachable address")
			}
		}
	default:
		ln.Close()
		return fmt.Errorf("server: invalid tls_mode %q", mode)
	}
	// Snapshot/replay needs every persistent mutation to pass through the
	// sequencer and a live EventBus, while UDP needs channel membership and relay
	// authority. Those adapters are not assembled yet, so neither listener is
	// public or bound. Starting either partial surface would let clients retain
	// stale ACL/presence/voice state.
	return a.serve(running, ln, tlsInfo, timeouts)
}

// validate rejects incomplete test-injected timeout policies before Run binds
// a listener, preserving startup's fail-fast behavior.
func (t HTTPTimeouts) validate() error {
	if t.ReadHeader <= 0 || t.Read <= 0 || t.Write <= 0 || t.Idle <= 0 {
		return errors.New("server: all HTTP timeouts must be positive")
	}
	return nil
}

// isWildcardHost reports whether host is a non-routable wildcard bind address.
func isWildcardHost(host string) bool {
	// A wildcard bind (0.0.0.0 or ::) is a listen address, not something a
	// client can connect to, so it must never be embedded in a join URL.
	return host == "0.0.0.0" || host == "::" || host == "[::]"
}

// serve publishes readiness only after every core listener is bound, starts the
// HTTP worker under supervisor, and owns graceful/fatal teardown. HTTP serving
// itself never initiates shutdown; it only reports an unexpected failure to the
// process supervisor.
func (a *App) serve(running *appRun, ln net.Listener, tlsInfo func(), timeouts HTTPTimeouts) error {
	if running == nil || running.supervisor == nil {
		_ = ln.Close()
		return errors.New("server: invalid process runtime")
	}
	supervisor := running.supervisor
	log := a.logger.With("module", "server")
	addr := ln.Addr().String()
	log.Info("http listening on: " + addr)
	if tlsInfo != nil {
		tlsInfo()
	}
	// The startup chant goes through the normal log pipeline (timestamp,
	// module, file sink). The reserved color attr makes it stand out in
	// magenta on terminals; files and pipes render it plain.
	log.Info("System initialization finished, LINK START!", "color", "magenta")
	srv := newHTTPServer(addr, a.echo, a.logger, timeouts)
	a.setRunServer(running, srv)
	supervisor.Go("http serve", func(context.Context) error {
		err := srv.Serve(ln)
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	})

	<-supervisor.Context().Done()
	if fatal := supervisor.FatalError(); fatal != nil {
		return a.fatalShutdown(srv, supervisor, fatal)
	}
	return a.gracefulShutdown(srv, supervisor, log)
}

// gracefulShutdown applies the currently assembled subset of the fixed staged
// order: stop new control admission, drain hijacked WS, stop UDP/purge, drain
// HTTP, wait workers, then close DB. Future sequencer/EventBus/timer/relay
// stages register at the marked boundaries without changing ownership.
func (a *App) gracefulShutdown(srv *http.Server, supervisor *ProcessSupervisor, log *slog.Logger) error {
	log.Info("shutting down")
	supervisor.BeginShutdown()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	connectionsErr := a.ShutdownConnections(shutdownCtx)
	voiceErr := a.stopVoice()
	httpErr := shutdownHTTPServer(shutdownCtx, srv)
	workersErr := supervisor.WaitWorkers(shutdownCtx)
	realtimeErr := a.stopRealtime(shutdownCtx)
	dbErr := a.closeDatabase()
	err := errors.Join(connectionsErr, voiceErr, httpErr, workersErr, realtimeErr, dbErr)
	if err == nil {
		log.Info("shutdown complete")
	}
	return err
}

// fatalShutdown does not attempt to drain the failed worker. It rejects new
// control admission, force-closes live sockets after best-effort terminal work,
// stops UDP/HTTP, waits only within an independent short deadline, then closes
// DB so restart reconstructs runtime state from persistent facts.
func (a *App) fatalShutdown(srv *http.Server, supervisor *ProcessSupervisor, cause error) error {
	supervisor.BeginShutdown()
	a.connections.StopAdmission()
	a.connections.DisconnectAll(4005, "server failure")
	a.connections.ForceCloseAll()
	voiceErr := a.stopVoice()
	httpErr := srv.Close()
	fatalCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	workersErr := supervisor.WaitWorkers(fatalCtx)
	realtimeErr := a.stopRealtime(fatalCtx)
	dbErr := a.closeDatabase()
	return errors.Join(cause, voiceErr, httpErr, workersErr, realtimeErr, dbErr)
}

// newHTTPServer builds the ordinary HTTP server with the fixed deadline and
// logging policy. WebSocket deadline ownership belongs to the future realtime
// layer once it hijacks a connection.
func newHTTPServer(addr string, handler http.Handler, logger *slog.Logger, timeouts HTTPTimeouts) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ErrorLog:          slog.NewLogLogger(logger.With("module", "http").Handler(), slog.LevelError),
		ReadHeaderTimeout: timeouts.ReadHeader,
		ReadTimeout:       timeouts.Read,
		WriteTimeout:      timeouts.Write,
		IdleTimeout:       timeouts.Idle,
	}
}

// shutdownHTTPServer drains ordinary HTTP connections, then force-closes any
// that remain after the caller's deadline. Close is required because Shutdown
// otherwise leaves slow or stuck connections alive after returning an error.
func shutdownHTTPServer(ctx context.Context, srv *http.Server) error {
	if err := srv.Shutdown(ctx); err != nil {
		return errors.Join(err, srv.Close())
	}
	return nil
}
