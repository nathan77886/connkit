package operations

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestSSHCommandUsesConnectionAuthorizationWithoutOperationFlags(t *testing.T) {
	s, actor, target, _ := fixture(t)
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	result := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			result <- err
			return
		}
		config := &ssh.ServerConfig{PasswordCallback: func(_ ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if string(password) != "fixture-password" {
				return nil, errors.New("authentication failed")
			}
			return nil, nil
		}}
		config.AddHostKey(signer)
		server, channels, requests, err := ssh.NewServerConn(conn, config)
		if err != nil {
			result <- err
			return
		}
		defer server.Close()
		go ssh.DiscardRequests(requests)
		channelRequest := <-channels
		channel, stream, err := channelRequest.Accept()
		if err != nil {
			result <- err
			return
		}
		defer channel.Close()
		req := <-stream
		var command struct{ Command string }
		if req.Type != "exec" || ssh.Unmarshal(req.Payload, &command) != nil || command.Command != "printf fixture" {
			result <- errors.New("unexpected command")
			return
		}
		if err = req.Reply(true, nil); err != nil {
			result <- err
			return
		}
		if _, err = channel.Write([]byte("fixture-output")); err != nil {
			result <- err
			return
		}
		_, err = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
		result <- err
	}()
	host, portText, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	raw, _ := json.Marshal(map[string]any{"host": host, "port": port, "username": "fixture", "password": "fixture-password", "host_key": strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))), "allow_exec": false})
	target.Type = "ssh"
	target.Secret, err = s.Store.Encrypt(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Store.DB.Save(&target).Error; err != nil {
		t.Fatal(err)
	}
	out, err := s.Run(t.Context(), actor, "ssh_exec", Input{ConnectionID: target.ID, Command: "printf fixture"})
	if err != nil || !strings.Contains(string(mustJSON(t, out)), "fixture-output") {
		t.Fatalf("command blocked: %v %v", out, err)
	}
	if err = <-result; err != nil {
		t.Fatal(err)
	}
	if _, err = s.Run(t.Context(), Actor{Token: "unknown"}, "ssh_exec", Input{ConnectionID: target.ID, Command: "printf fixture"}); err == nil {
		t.Fatal("connection authentication bypassed")
	}
}
