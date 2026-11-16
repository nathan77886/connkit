package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/nathan77886/connkit/internal/config"
	"github.com/nathan77886/connkit/internal/operations"
	"github.com/nathan77886/connkit/internal/store"
	service "github.com/nathan77886/connkit/mcp"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--healthcheck" {
		client := &http.Client{Timeout: 2 * time.Second}
		r, e := client.Get("http://127.0.0.1:8081/healthz")
		if e != nil {
			os.Exit(1)
		}
		r.Body.Close()
		if r.StatusCode != 200 {
			os.Exit(1)
		}
		return
	}
	s, err := store.OpenDatabase(config.Env("CONNKIT_DB_DRIVER", "sqlite"), config.DatabaseSource(), os.Getenv("CONNKIT_MASTER_KEY"), false)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := s.Close(); err != nil {
			log.Print(err)
		}
	}()
	var cidrs []netip.Prefix
	for _, raw := range split(os.Getenv("CONNKIT_MCP_TRUSTED_CIDRS")) {
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			log.Fatal("invalid trusted CIDR: ", err)
		}
		cidrs = append(cidrs, p)
	}
	origins := split(os.Getenv("CONNKIT_MCP_ORIGINS"))
	ops := &operations.Service{Store: s}
	ops.Desktop = operations.NewDesktopManager(ops)
	defer ops.Desktop.Close()
	servers := []*http.Server{{Addr: config.Env("CONNKIT_MCP_ADDR", ":8081"), Handler: service.NewWithOperations(s, false, nil, origins, ops), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second}}
	if addr := os.Getenv("CONNKIT_MCP_ANONYMOUS_ADDR"); addr != "" {
		servers = append(servers, &http.Server{Addr: addr, Handler: service.NewWithOperations(s, true, cidrs, origins, ops), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second})
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	failures := make(chan error, len(servers))
	for _, server := range servers {
		go func() { log.Printf("MCP listening on %s", server.Addr); failures <- server.ListenAndServe() }()
	}
	select {
	case <-ctx.Done():
	case err := <-failures:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Print(err)
		}
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, server := range servers {
		if err := server.Shutdown(shutdown); err != nil {
			log.Print(err)
		}
	}
}
func split(value string) []string {
	var out []string
	for _, v := range strings.Split(value, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}
