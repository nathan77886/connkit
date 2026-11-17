package operations

import (
	"encoding/json"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Set only for disposable local fixture instances; never point at a live database.
func TestNativeMySQLAndRedisFixtures(t *testing.T) {
	for _, protocol := range []string{"mysql", "redis"} {
		t.Run(protocol, func(t *testing.T) {
			addr := os.Getenv("CONNKIT_FIXTURE_" + strings.ToUpper(protocol))
			if addr == "" {
				t.Skip("disposable native fixture not configured")
			}
			host, portString, err := net.SplitHostPort(addr)
			if err != nil {
				t.Fatal(err)
			}
			port, err := strconv.Atoi(portString)
			if err != nil {
				t.Fatal(err)
			}
			s, a, c, _ := fixture(t)
			cfg := Settings{Host: host, Port: port}
			if protocol == "mysql" {
				cfg.Username = "root"
				cfg.Password = "connkit-disposable-fixture"
				cfg.Database = "fixture"
			}
			raw, _ := json.Marshal(cfg)
			c.Secret, _ = s.Store.Encrypt(raw)
			c.Type = protocol
			s.Store.DB.Save(&c)
			call := func(tool string, in Input) (any, error) {
				in.ConnectionID = c.ID
				return s.Run(t.Context(), a, tool, in)
			}
			deadline := time.Now().Add(45 * time.Second)
			for {
				_, err = call("connection_test", Input{})
				if err == nil {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("fixture readiness: %v", err)
				}
				time.Sleep(300 * time.Millisecond)
			}
			if protocol == "mysql" {
				for _, query := range []string{"CREATE TABLE sample (id BIGINT PRIMARY KEY, value VARCHAR(80))", "INSERT INTO sample (id,value) VALUES (9007199254740993,'native-driver')"} {
					if _, err = call("db_execute", Input{Query: query}); err != nil {
						t.Fatal(err)
					}
				}
				var input Input
				if err = json.Unmarshal([]byte(`{"query":"SELECT value FROM sample WHERE id = ?","params":[9007199254740993]}`), &input); err != nil {
					t.Fatal(err)
				}
				out, err := call("db_query", input)
				if err != nil || !strings.Contains(string(mustJSON(t, out)), "native-driver") {
					t.Fatalf("native query %v %v", out, err)
				}
				if _, err = call("db_query", Input{Query: "DELETE FROM sample"}); err == nil {
					t.Fatal("MySQL read-only transaction allowed deletion")
				}
				if _, err = call("db_schema", Input{Table: "sample"}); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err = call("redis_command", Input{Command: "SET", Args: []string{"connkit-fixture", "native-driver"}}); err != nil {
					t.Fatal(err)
				}
				out, err := call("redis_read", Input{Command: "GETRANGE", Args: []string{"connkit-fixture", "0", "99"}})
				if err != nil || !strings.Contains(string(mustJSON(t, out)), "native-driver") {
					t.Fatalf("Redis query %v %v", out, err)
				}
				if _, err = call("redis_scan", Input{Pattern: "connkit-*"}); err != nil {
					t.Fatal(err)
				}
				if _, err = call("redis_command", Input{Command: "DEL", Args: []string{"connkit-fixture"}}); err != nil {
					t.Fatal(err)
				}

			}
		})
	}
}
