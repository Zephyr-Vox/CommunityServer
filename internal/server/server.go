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

// RunOptions carries per-invocation startup switches that are not part of the
// persisted configuration. Keeping them out of ServerConfig makes it obvious
// that flags like -force-regenerate-cert are one-shot operator actions.
type RunOptions struct {
	ForceRegenerateCert bool
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
			return errors.New("server: -force-regenerate-cert requires tls_mode optional or required")
		}
	case config.TLSModeRequired, config.TLSModeOptional:
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
			NextProtos:   []string{"http/1.1"},
			Certificates: []tls.Certificate{bundle.Certificate},
		}
		if mode == config.TLSModeRequired {
			ln = tls.NewListener(ln, tlsCfg)
		} else {
			ln = newSniffListener(ln, tlsCfg)
		}
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
	return a.serve(ctx, ln, tlsInfo)
}

func isWildcardHost(host string) bool {
	// A wildcard bind (0.0.0.0 or ::) is a listen address, not something a
	// client can connect to, so it must never be embedded in a join URL.
	return host == "0.0.0.0" || host == "::" || host == "[::]"
}

func (a *App) serve(ctx context.Context, ln net.Listener, tlsInfo func()) error {
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
	srv := &http.Server{
		Addr:     addr,
		Handler:  a.echo,
		ErrorLog: slog.NewLogLogger(a.logger.With("module", "http").Handler(), slog.LevelError),
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Serve(ln)
	}()

	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		log.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		err := srv.Shutdown(shutdownCtx)
		if err == nil {
			log.Info("shutdown complete")
		}
		return err
	}
}
