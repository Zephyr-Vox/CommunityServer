package server

import (
	"context"
	"errors"
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
	srv := &http.Server{Addr: addr, Handler: a.echo}

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}
