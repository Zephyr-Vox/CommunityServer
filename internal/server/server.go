package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"
)

// shutdownTimeout is how long Run waits for in-flight requests to drain after
// the context is cancelled.
const shutdownTimeout = 10 * time.Second

// Run listens on cfg.Server.Host:HTTPPort and serves until ctx is cancelled,
// then shuts the server down gracefully and returns.
func (a *App) Run(ctx context.Context) error {
	addr := net.JoinHostPort(a.cfg.Server.Host, strconv.Itoa(a.cfg.Server.HTTPPort))
	log := a.logger.With("module", "server")

	// Bind before claiming readiness: a goroutine-based ListenAndServe would
	// hide a bind failure, letting "http listening"/"LINK START" print even
	// though the process is about to exit with an error.
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("server: listen %s: %w", addr, err)
	}
	log.Info("http listening on: " + addr)
	// The startup chant goes through the normal log pipeline (timestamp,
	// module, file sink). The reserved color attr makes it stand out in
	// magenta on terminals; files and pipes render it plain.
	log.Info("System initialization finished, LINK START!", "color", "magenta")

	srv := &http.Server{Addr: addr, Handler: a.echo}
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
