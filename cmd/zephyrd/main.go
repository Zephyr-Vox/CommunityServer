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
	"zephyr.vox/server/ce/internal/server"
)

func main() {
	if err := run(); err != nil {
		slog.Error("zephyrd exited with error", "error", err)
		os.Exit(1)
	}
}

func run() error {
	appConfigPath := flag.String("config", "config/zephyr.toml", "path to zephyr.toml (generated on first start)")
	rolesPath := flag.String("roles", "config/roles.yaml", "path to roles.yaml (generated on first start)")
	flag.Parse()

	appConfig, err := config.LoadApp(*appConfigPath)
	if err != nil {
		return err
	}
	roles, err := config.LoadRoles(*rolesPath)
	if err != nil {
		return err
	}

	app, err := server.New(appConfig, roles)
	if err != nil {
		return err
	}
	defer app.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	slog.Info("zephyrd starting",
		"addr", appConfig.Server.Host+":"+strconv.Itoa(appConfig.Server.HTTPPort),
		"db", appConfig.Server.DBPath)
	return app.Run(ctx)
}
