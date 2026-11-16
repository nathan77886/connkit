package operations

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/nathan77886/connkit/internal/route"
	"github.com/nathan77886/connkit/internal/store"
)

func rdpPin(cfg Settings) ([]byte, error) {
	p, e := hex.DecodeString(cfg.CertificateSHA256)
	if e != nil || len(p) != 32 {
		return nil, errors.New("RDP requires explicit certificate_sha256 (64 hexadecimal characters)")
	}
	return p, nil
}

// rdpProbe does no user authentication and closes its transport on every path.
func (s *Service) rdpProbe(ctx context.Context, c store.Connection, cfg Settings) (map[string]any, error) {
	pin, err := rdpPin(cfg)
	if err != nil {
		return nil, err
	}
	addr, err := address(cfg, 3389)
	if err != nil {
		return nil, err
	}
	conn, err := (&route.Dialer{Store: s.Store}).DialContext(ctx, c.ProxyID, addr)
	if err != nil {
		return nil, fmt.Errorf("RDP TCP/route failed: %w", err)
	}
	defer conn.Close()
	if d, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(d)
	}
	// TPKT + X.224 request; request TLS and HYBRID (NLA), no legacy RDP security.
	packet := []byte{3, 0, 0, 19, 14, 0xe0, 0, 0, 0, 0, 0, 1, 0, 8, 0, 3, 0, 0, 0}
	if _, err = conn.Write(packet); err != nil {
		return nil, errors.New("RDP negotiation write failed or timed out")
	}
	header := make([]byte, 4)
	if _, err = io.ReadFull(conn, header); err != nil {
		return nil, errors.New("RDP negotiation response failed or timed out")
	}
	n := int(binary.BigEndian.Uint16(header[2:]))
	if header[0] != 3 || header[1] != 0 || n < 19 || n > 4096 {
		return nil, errors.New("invalid RDP negotiation response")
	}
	body := make([]byte, n-4)
	if _, err = io.ReadFull(conn, body); err != nil {
		return nil, errors.New("incomplete RDP negotiation response or timeout")
	}
	if body[1] != 0xd0 || int(body[0])+1 != len(body) {
		return nil, errors.New("invalid RDP X.224 response")
	}
	neg := body[len(body)-8:]
	if binary.LittleEndian.Uint16(neg[2:4]) != 8 {
		return nil, errors.New("invalid RDP negotiation length")
	}
	if neg[0] == 3 {
		return nil, fmt.Errorf("RDP negotiation rejected (code %d)", binary.LittleEndian.Uint32(neg[4:]))
	}
	protocol := binary.LittleEndian.Uint32(neg[4:])
	if neg[0] != 2 || (protocol != 1 && protocol != 2) {
		return nil, errors.New("server did not select supported TLS/NLA security")
	}
	secure := tls.Client(conn, &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true, // Explicit leaf SHA256 pin is the trust anchor, including self-signed certificates.
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("RDP certificate missing")
			}
			sum := sha256.Sum256(state.PeerCertificates[0].Raw)
			if subtle.ConstantTimeCompare(pin, sum[:]) != 1 {
				return errors.New("RDP certificate SHA256 mismatch; connection refused")
			}
			return nil
		}})
	if err = secure.HandshakeContext(ctx); err != nil {
		if strings.Contains(err.Error(), "mismatch") {
			return nil, errors.New("RDP certificate SHA256 mismatch; connection refused")
		}
		return nil, errors.New("RDP TLS handshake failed or timed out")
	}
	return map[string]any{"tcp_connected": true, "protocol_negotiated": true, "selected_protocol": protocol, "tls_verified": true, "tls_version": tls.VersionName(secure.ConnectionState().Version), "certificate_sha256": strings.ToLower(cfg.CertificateSHA256), "user_authenticated": false, "desktop_session": false, "stage": "negotiated_unauthenticated", "message": "RDP negotiation and pinned TLS succeeded; user authentication not attempted"}, nil
}
func (s *Service) rdpTest(ctx context.Context, c store.Connection, cfg Settings) (any, error) {
	result, err := s.rdpProbe(ctx, c, cfg)
	if err != nil {
		return nil, err
	}
	if cfg.Username == "" || cfg.Password == "" {
		result["credentials_missing"] = true
		return result, nil
	}
	if result["selected_protocol"] != uint32(2) {
		return nil, errors.New("RDP NLA required for credential authentication")
	}
	worker, err := s.startRDP(ctx, c, cfg, 800, 600, true)
	if err != nil {
		return nil, err
	}
	defer worker.close()
	result["user_authenticated"] = true
	result["stage"] = "authenticated"
	result["message"] = "FreeRDP NLA authentication succeeded; no desktop session requested"
	return result, nil
}

// relay binds only to loopback, and forwards exclusively to the stored target via route.
func (s *Service) relay(ctx context.Context, c store.Connection, cfg Settings) (net.Listener, error) {
	addr, err := address(cfg, 3389)
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, errors.New("RDP relay unavailable")
	}
	stop := context.AfterFunc(ctx, func() { listener.Close() })
	go func() {
		defer stop()
		defer listener.Close()
		for attempts := 0; attempts < 3; attempts++ {
			local, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer local.Close()
				up, err := (&route.Dialer{Store: s.Store}).DialContext(ctx, c.ProxyID, addr)
				if err != nil {
					return
				}
				defer up.Close()
				done := make(chan struct{})
				go func() { io.Copy(up, local); up.Close(); close(done) }()
				io.Copy(local, up)
				local.Close()
				<-done
			}()
		}
	}()
	return listener, nil
}
