package main

import (
	"context"
	"errors"
	"github.com/nathan77886/connkit/internal/config"
	"github.com/nathan77886/connkit/internal/store"
	service "github.com/nathan77886/connkit/mcp"
	"log"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	s, err := store.Open(config.Env("CONNKIT_DB_PATH", "data/connkit.db"), os.Getenv("CONNKIT_MASTER_KEY"), false)
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
	servers := []*http.Server{{Addr: config.Env("CONNKIT_MCP_ADDR", ":8081"), Handler: service.New(s, false, nil, origins), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second}}
	if addr := os.Getenv("CONNKIT_MCP_ANONYMOUS_ADDR"); addr != "" {
		servers = append(servers, &http.Server{Addr: addr, Handler: service.New(s, true, cidrs, origins), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second})
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
