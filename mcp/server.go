// Package mcp exposes ConnKit's agent-facing Streamable HTTP service.
package mcp

import (
	"context"
	"errors"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/nathan77886/connkit/internal/files"
	"github.com/nathan77886/connkit/internal/operations"
	"github.com/nathan77886/connkit/internal/store"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// New creates either a key-authenticated or an explicitly anonymous listener.
// Stateless transport keeps request credentials out of reusable MCP sessions.
func New(s *store.Store, anonymous bool, cidrs []netip.Prefix, origins []string) http.Handler {
	return NewWithOperations(s, anonymous, cidrs, origins, &operations.Service{Store: s})
}

// NewWithOperations shares a process-wide desktop session manager across listeners.
func NewWithOperations(s *store.Store, anonymous bool, cidrs []netip.Prefix, origins []string, ops *operations.Service) http.Handler {
	transport := sdk.NewStreamableHTTPHandler(func(r *http.Request) *sdk.Server {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		server := sdk.NewServer(&sdk.Implementation{Name: "connkit", Version: "0.1.0-dev"}, nil)
		sdk.AddTool(server, &sdk.Tool{Name: "connections_list", Description: "List accessible registered connections."}, func(ctx context.Context, _ *sdk.CallToolRequest, _ struct{}) (*sdk.CallToolResult, any, error) {
			connections, err := s.AuthorizedConnections(ctx, token, anonymous)
			if err != nil {
				return nil, nil, errors.New("connection access denied")
			}
			return nil, map[string]any{"connections": connections}, nil
		})
		service := files.New(s)
		actor := files.Actor{Token: token, Anonymous: anonymous}
		sdk.AddTool(server, &sdk.Tool{Name: "files_prepare_upload", Description: "Prepare a private S3 upload bound to an SSH target and absolute path. PUT the bytes to the returned URL using its headers, then call files_deliver."}, func(ctx context.Context, _ *sdk.CallToolRequest, in files.PrepareInput) (*sdk.CallToolResult, any, error) {
			out, err := service.Prepare(ctx, actor, in)
			return nil, out, err
		})
		sdk.AddTool(server, &sdk.Tool{Name: "files_deliver", Description: "After uploading, ask the target to download and verify the file. Existing destination files are never overwritten. Do not automatically retry an unknown outcome."}, func(ctx context.Context, _ *sdk.CallToolRequest, in fileInput) (*sdk.CallToolResult, any, error) {
			out, err := service.Deliver(ctx, actor, in.ID)
			return nil, out, err
		})
		sdk.AddTool(server, &sdk.Tool{Name: "files_status", Description: "Read transfer state without exposing signed URLs or credentials."}, func(ctx context.Context, _ *sdk.CallToolRequest, in fileInput) (*sdk.CallToolResult, any, error) {
			out, err := service.Status(ctx, actor, in.ID)
			return nil, out, err
		})
		sdk.AddTool(server, &sdk.Tool{Name: "files_remove", Description: "Delete the staged cloud object; leaves the target file unchanged. Upload URLs remain valid until their expiry."}, func(ctx context.Context, _ *sdk.CallToolRequest, in fileInput) (*sdk.CallToolResult, any, error) {
			err := service.Remove(ctx, actor, in.ID)
			return nil, map[string]bool{"removed": err == nil}, err
		})
		caller, _, _ := net.SplitHostPort(r.RemoteAddr)
		registerOperations(server, s, token, anonymous, caller, ops)
		return server
	}, &sdk.StreamableHTTPOptions{Stateless: true})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			db, err := s.DB.DB()
			if err != nil || db.PingContext(r.Context()) != nil {
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
				return
			}
			_, _ = w.Write([]byte("ok\n"))
			return
		}
		if r.URL.Path != "/mcp" {
			http.NotFound(w, r)
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" && !contains(origins, origin) {
			http.Error(w, "origin denied", http.StatusForbidden)
			return
		}
		if anonymous {
			policy, err := s.AccessPolicy(r.Context())
			if err != nil {
				http.Error(w, "access policy unavailable", http.StatusServiceUnavailable)
				return
			}
			if len(policy.AnonymousCIDRs) > 0 {
				host, _, err := net.SplitHostPort(r.RemoteAddr)
				addr, parseErr := netip.ParseAddr(host)
				allowed := false
				if err == nil && parseErr == nil {
					for _, raw := range policy.AnonymousCIDRs {
						prefix, e := netip.ParsePrefix(raw)
						if e == nil && prefix.Contains(addr.Unmap()) {
							allowed = true
							break
						}
					}
				}
				if !allowed {
					http.Error(w, "source denied", http.StatusForbidden)
					return
				}
			}
		}
		if anonymous && len(cidrs) > 0 {
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			addr, e := netip.ParseAddr(host)
			allowed := false
			if err == nil && e == nil {
				for _, prefix := range cidrs {
					if prefix.Contains(addr.Unmap()) {
						allowed = true
						break
					}
				}
			}
			if !allowed {
				http.Error(w, "source denied", http.StatusForbidden)
				return
			}
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
		defer cancel()
		r = r.WithContext(ctx)
		if !anonymous {
			header := r.Header.Get("Authorization")
			if !strings.HasPrefix(header, "Bearer ") {
				w.Header().Set("WWW-Authenticate", "Bearer")
				http.Error(w, "API key required", http.StatusUnauthorized)
				return
			}
			if _, err := s.AuthorizedConnections(ctx, strings.TrimPrefix(header, "Bearer "), false); err != nil {
				http.Error(w, "invalid API key", http.StatusUnauthorized)
				return
			}
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		transport.ServeHTTP(w, r)
	})
}
func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}

type fileInput struct {
	ID string `json:"id"`
}
