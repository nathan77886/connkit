package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/nathan77886/connkit/admin"
	"github.com/nathan77886/connkit/internal/config"
	"github.com/nathan77886/connkit/internal/store"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	s, err := store.OpenDatabase(config.Env("CONNKIT_DB_DRIVER", "sqlite"), config.DatabaseSource(), os.Getenv("CONNKIT_MASTER_KEY"), true)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := s.Close(); err != nil {
			log.Print(err)
		}
	}()
	app, err := admin.New(s, config.Env("CONNKIT_ADMIN_USERNAME", "admin"), os.Getenv("CONNKIT_ADMIN_PASSWORD"))
	if err != nil {
		log.Fatal(err)
	}
	s.StartCallCleanup(ctx, log.Printf)
	if err := app.Listen(config.Env("CONNKIT_ADMIN_ADDR", "127.0.0.1:8080")); err != nil {
		log.Fatal(err)
	}
}
