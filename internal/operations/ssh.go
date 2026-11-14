package operations

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"sync"

	"github.com/nathan77886/connkit/internal/route"
	"github.com/nathan77886/connkit/internal/store"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

type boundedBuffer struct {
	mu        sync.Mutex
	b         []byte
	truncated bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	remaining := MaxBytes/4 - len(b.b)
	if len(p) > remaining {
		p = p[:remaining]
		b.truncated = true
	}
	b.b = append(b.b, p...)
	return n, nil
}

func (s *Service) ssh(ctx context.Context, c store.Connection, cfg Settings, tool string, in Input) (any, error) {
	if tool != "ssh_exec" && tool != "sftp_read" && tool != "ssh_test" {
		return nil, errors.New("unsupported SSH operation")
	}
	if tool == "ssh_exec" && (!cfg.AllowExec || strings.TrimSpace(in.Command) == "") {
		return nil, errors.New("allow_exec and a command are required")
	}
	client, err := (&route.Dialer{Store: s.Store}).OpenSSH(ctx, c)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	if tool == "ssh_test" {
		return map[string]any{"ok": true, "stage": "authenticated", "operation_tested": false}, nil
	}
	if tool == "sftp_read" {
		sc, err := sftp.NewClient(client)
		if err != nil {
			return nil, errors.New("SFTP initialization failed")
		}
		defer sc.Close()
		f, err := sc.Open(in.Path)
		if err != nil {
			return nil, errors.New("SFTP open failed")
		}
		defer f.Close()
		raw, err := io.ReadAll(io.LimitReader(f, MaxBytes/2+1))
		if err != nil {
			return nil, errors.New("SFTP read failed")
		}
		truncated := len(raw) > MaxBytes/2
		if truncated {
			raw = raw[:MaxBytes/2]
		}
		return map[string]any{"encoding": "base64", "data": base64.StdEncoding.EncodeToString(raw), "truncated": truncated}, nil
	}
	session, err := client.NewSession()
	if err != nil {
		return nil, errors.New("SSH session failed")
	}
	defer session.Close()
	stdout, stderr := &boundedBuffer{}, &boundedBuffer{}
	session.Stdout = stdout
	session.Stderr = stderr
	err = session.Run(in.Command)
	if ctx.Err() != nil {
		return nil, errors.New("SSH interrupted; command outcome is unknown, do not automatically retry")
	}
	code := 0
	if err != nil {
		var exit *ssh.ExitError
		if !errors.As(err, &exit) {
			return nil, errors.New("SSH transport failed; command outcome is unknown")
		}
		code = exit.ExitStatus()
	}
	return map[string]any{"stdout": string(stdout.b), "stderr": string(stderr.b), "exit_code": code, "truncated": stdout.truncated || stderr.truncated}, nil
}
