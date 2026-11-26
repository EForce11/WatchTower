package config

import (
	"errors"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func writeFile(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "turret.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadDefaults(t *testing.T) {
	old := lookupUser
	lookupUser = func(name string) (*user.User, error) {
		if name != "watchtower" {
			t.Fatalf("unexpected lookup %q", name)
		}
		return &user.User{Uid: "998"}, nil
	}
	defer func() { lookupUser = old }()

	c, err := Load(writeFile(t, "agent_id: a1\ncore_endpoint: \"10.8.0.1:50051\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := Config{
		AgentID:       "a1",
		SocketPath:    "/run/watchtower/turret.sock",
		SocketGroup:   "watchtower",
		AllowedUIDs:   []int{998},
		AutomationKey: "/etc/watchtower/automation.pub",
		AdminKeysDir:  "/etc/watchtower/admin_keys.d",
		IOCBundlePath: "/var/lib/watchtower/ioc.bundle",
		StateDir:      "/var/lib/watchtower/turret",
		WhitelistFile: "/etc/watchtower/whitelist.txt",
		CoreEndpoint:  "10.8.0.1:50051",
		WireGuardCIDR: "10.8.0.0/24",
		ReflexBudget:  Budget{MaxTargets: 50, Window: 10 * time.Minute},
		PrefixLimiter: Limiter{Threshold: 10, Window: 60 * time.Second},
	}
	if !reflect.DeepEqual(c, want) {
		t.Fatalf("got %+v\nwant %+v", c, want)
	}
}

func TestLoadNoWatchtowerUser(t *testing.T) {
	old := lookupUser
	lookupUser = func(string) (*user.User, error) { return nil, user.UnknownUserError("watchtower") }
	defer func() { lookupUser = old }()
	c, err := Load(writeFile(t, "agent_id: a1\ncore_endpoint: \"10.8.0.1:50051\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.AllowedUIDs) != 0 {
		t.Fatalf("want empty AllowedUIDs, got %v", c.AllowedUIDs)
	}
}

func TestLoadExplicitValues(t *testing.T) {
	c, err := Load(writeFile(t, `agent_id: a1
core_endpoint: "10.8.0.1:50051"
allowed_uids: [1000]
reflex_budget:
  max_targets: 5
  window: 2m
prefix_limiter:
  threshold: 3
  window: 30s
`))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(c.AllowedUIDs, []int{1000}) ||
		c.ReflexBudget != (Budget{5, 2 * time.Minute}) ||
		c.PrefixLimiter != (Limiter{3, 30 * time.Second}) {
		t.Fatalf("unexpected %+v", c)
	}
}

func TestLoadUnknownKey(t *testing.T) {
	if _, err := Load(writeFile(t, "agent_id: a1\ncore_endpoint: \"10.8.0.1:1\"\nbogus: 1\n")); err == nil {
		t.Fatal("want error for unknown key")
	}
}

func TestLoadBadDuration(t *testing.T) {
	if _, err := Load(writeFile(t, "agent_id: a1\ncore_endpoint: \"10.8.0.1:1\"\nreflex_budget:\n  window: nope\n")); err == nil {
		t.Fatal("want error for bad duration")
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "nope.yaml"))
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("want ErrNotExist, got %v", err)
	}
}

func TestValidate(t *testing.T) {
	good := func() Config {
		return Config{
			AgentID:       "a1",
			SocketPath:    "/run/watchtower/turret.sock",
			CoreEndpoint:  "10.8.0.1:50051",
			WireGuardCIDR: "10.8.0.0/24",
			ReflexBudget:  Budget{MaxTargets: 50, Window: time.Minute},
			PrefixLimiter: Limiter{Threshold: 10, Window: time.Minute},
		}
	}
	if err := good().Validate(); err != nil {
		t.Fatalf("good config: %v", err)
	}
	cases := []struct {
		name string
		mut  func(*Config)
		want string
	}{
		{"empty agent_id", func(c *Config) { c.AgentID = "" }, "agent_id"},
		{"hostname endpoint", func(c *Config) { c.CoreEndpoint = "core.example:50051" }, "must be an IP"},
		{"endpoint no port", func(c *Config) { c.CoreEndpoint = "10.8.0.1" }, "core_endpoint"},
		{"bad cidr", func(c *Config) { c.WireGuardCIDR = "not-a-cidr" }, "wireguard_cidr"},
		{"budget zero", func(c *Config) { c.ReflexBudget.MaxTargets = 0 }, "max_targets"},
		{"limiter negative", func(c *Config) { c.PrefixLimiter.Threshold = -1 }, "threshold"},
		{"relative socket", func(c *Config) { c.SocketPath = "turret.sock" }, "socket_path"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := good()
			tc.mut(&c)
			err := c.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}
