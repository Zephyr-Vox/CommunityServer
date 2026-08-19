// Command zephyrd runs the ZephyrVox CommunityServer HTTP service.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"zephyr.vox/server/ce/internal/config"
	"zephyr.vox/server/ce/internal/logging"
	"zephyr.vox/server/ce/internal/server"
)

// main exits with the status selected by run.
func main() {
	printBanner()
	if err := run(); err != nil {
		slog.With("module", "main").Error("zephyrd exited with error: " + err.Error())
		os.Exit(1)
	}
}

// run loads configuration and starts the server process.
func run() error {
	appConfigPath := flag.String("config", "config/zephyr.toml", "path to zephyr.toml (generated on first start)")
	forceRegenerateCert := flag.Bool("force-regenerate-cert", false,
		"regenerate the auto-generated self-signed certificate on startup (auto mode only)")
	flag.Parse()

	appConfig, err := config.LoadApp(*appConfigPath)
	if err != nil {
		return err
	}
	logger, cleanup, err := newLogger(appConfig.Log)
	if err != nil {
		return err
	}
	defer cleanup()
	slog.SetDefault(logger)
	log := slog.With("module", "main")

	app, err := server.New(appConfig, logger)
	if err != nil {
		return err
	}
	defer app.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	code, pending, err := app.EnsureActivationCode(ctx)
	if err != nil {
		return err
	}
	if pending {
		// The plaintext is available exactly once: after this log line only
		// its digest remains in memory.
		log.Info("first owner activation required code: " + code)
	} else {
		log.Info("installation initialized; first-owner activation is disabled")
	}

	addr := appConfig.Server.Host + ":" + strconv.Itoa(appConfig.Server.HTTPPort)
	log.Info("zephyrd starting on " + addr + ", db " + appConfig.Server.DBPath)
	return app.Run(ctx, server.RunOptions{ForceRegenerateCert: *forceRegenerateCert})
}

// newLogger builds the human-readable logger: stdout always, plus a rotating
// file sink when log.path is configured. The returned cleanup closes the file
// sink; it must run after the app has shut down so shutdown logs are kept.
func newLogger(cfg config.LogConfig) (*slog.Logger, func(), error) {
	lv := new(slog.LevelVar)
	lv.Set(cfg.Level)

	// Console handler: colors are auto-enabled only when stdout is a terminal.
	console := logging.NewTextHandler(os.Stdout, lv)
	handlers := []slog.Handler{console}
	cleanup := func() {}

	if cfg.Path != "" {
		rot, err := logging.NewRotatingWriter(cfg.Path, logging.RotatingWriterConfig{
			Keep:    cfg.ArchiveKeep,
			OnError: logging.ReportTo(console),
		})
		if err != nil {
			return nil, nil, err
		}
		cleanup = func() { rot.Close() }
		// The rotating writer is not an *os.File, so TTY detection disables
		// colors automatically; ANSI escapes never reach the archive.
		handlers = append(handlers, logging.NewTextHandler(rot, lv))
	}

	return slog.New(logging.NewFanout(handlers...)), cleanup, nil
}
