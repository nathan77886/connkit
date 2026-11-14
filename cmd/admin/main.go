package main

import (
	"github.com/nathan77886/connkit/admin"
	"github.com/nathan77886/connkit/internal/config"
	"github.com/nathan77886/connkit/internal/store"
	"log"
	"os"
)

func main() {
	s, err := store.Open(config.Env("CONNKIT_DB_PATH", "data/connkit.db"), os.Getenv("CONNKIT_MASTER_KEY"), true)
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
	if err := app.Listen(config.Env("CONNKIT_ADMIN_ADDR", "127.0.0.1:8080")); err != nil {
		log.Fatal(err)
	}
}
