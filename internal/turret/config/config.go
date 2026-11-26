// Package config loads and validates the wt-turret daemon configuration.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"
)

// lookupUser resolves the default socket peer; replaced in tests.
var lookupUser = user.Lookup

// Budget bounds how many targets reflex actions may touch per window.
type Budget struct {
	MaxTargets int           `yaml:"max_targets"`
	Window     time.Duration `yaml:"window"`
}

// Limiter is a per-prefix rate limiter.
type Limiter struct {
	Threshold int           `yaml:"threshold"`
	Window    time.Duration `yaml:"window"`
}

// parseWindow parses a duration string such as "10m"; empty keeps the default.
func parseWindow(s string, dst *time.Duration) error {
	if s == "" {
		return nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("window: %w", err)
	}
	*dst = d
	return nil
}

// UnmarshalYAML decodes onto the receiver, keeping any pre-set defaults for
// omitted keys.
func (b *Budget) UnmarshalYAML(n *yaml.Node) error {
	aux := struct {
		MaxTargets int    `yaml:"max_targets"`
		Window     string `yaml:"window"`
	}{MaxTargets: b.MaxTargets}
	if err := decodeKnown(n, &aux); err != nil {
		return err
	}
	b.MaxTargets = aux.MaxTargets
	return parseWindow(aux.Window, &b.Window)
}

// UnmarshalYAML decodes onto the receiver, keeping any pre-set defaults for
// omitted keys.
func (l *Limiter) UnmarshalYAML(n *yaml.Node) error {
	aux := struct {
		Threshold int    `yaml:"threshold"`
		Window    string `yaml:"window"`
	}{Threshold: l.Threshold}
	if err := decodeKnown(n, &aux); err != nil {
		return err
	}
	l.Threshold = aux.Threshold
	return parseWindow(aux.Window, &l.Window)
}

// decodeKnown decodes a node rejecting unknown keys.
func decodeKnown(n *yaml.Node, v any) error {
	buf, err := yaml.Marshal(n)
	if err != nil {
		return err
	}
	return strictUnmarshal(buf, v)
}

func strictUnmarshal(data []byte, v any) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	return dec.Decode(v)
}

// Config is the wt-turret configuration.
type Config struct {
	AgentID       string  `yaml:"agent_id"`
	SocketPath    string  `yaml:"socket_path"`
	SocketGroup   string  `yaml:"socket_group"`
	AllowedUIDs   []int   `yaml:"allowed_uids"`
	AutomationKey string  `yaml:"automation_key"`
	AdminKeysDir  string  `yaml:"admin_keys_dir"`
	IOCBundlePath string  `yaml:"ioc_bundle"`
	StateDir      string  `yaml:"state_dir"`
	WhitelistFile string  `yaml:"whitelist_file"`
	CoreEndpoint  string  `yaml:"core_endpoint"`
	WireGuardCIDR string  `yaml:"wireguard_cidr"`
	ReflexBudget  Budget  `yaml:"reflex_budget"`
	PrefixLimiter Limiter `yaml:"prefix_limiter"`
}

func defaults() Config {
	return Config{
		SocketPath:    "/run/watchtower/turret.sock",
		SocketGroup:   "watchtower",
		AutomationKey: "/etc/watchtower/automation.pub",
		AdminKeysDir:  "/etc/watchtower/admin_keys.d",
		IOCBundlePath: "/var/lib/watchtower/ioc.bundle",
		StateDir:      "/var/lib/watchtower/turret",
		WhitelistFile: "/etc/watchtower/whitelist.txt",
		WireGuardCIDR: "10.8.0.0/24",
		ReflexBudget:  Budget{MaxTargets: 50, Window: 10 * time.Minute},
		PrefixLimiter: Limiter{Threshold: 10, Window: 60 * time.Second},
	}
}

// Load reads path, applies defaults and validates. A missing file yields an
// error wrapping fs.ErrNotExist.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read turret config: %w", err)
	}
	c := defaults()
	if err := strictUnmarshal(data, &c); err != nil {
		return Config{}, fmt.Errorf("parse turret config %s: %w", path, err)
	}
	if len(c.AllowedUIDs) == 0 {
		if u, err := lookupUser("watchtower"); err == nil {
			if uid, err := strconv.Atoi(u.Uid); err == nil {
				c.AllowedUIDs = []int{uid}
			}
		}
	}
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

// Validate checks the configuration for usability.
func (c Config) Validate() error {
	if c.AgentID == "" {
		return errors.New("turret config: agent_id is required")
	}
	if !filepath.IsAbs(c.SocketPath) {
		return fmt.Errorf("turret config: socket_path %q must be absolute", c.SocketPath)
	}
	host, _, err := net.SplitHostPort(c.CoreEndpoint)
	if err != nil {
		return fmt.Errorf("turret config: core_endpoint %q: %w", c.CoreEndpoint, err)
	}
	if _, err := netip.ParseAddr(host); err != nil {
		return fmt.Errorf("turret config: core_endpoint host %q must be an IP literal", host)
	}
	if _, err := netip.ParsePrefix(c.WireGuardCIDR); err != nil {
		return fmt.Errorf("turret config: wireguard_cidr %q: %w", c.WireGuardCIDR, err)
	}
	if c.ReflexBudget.MaxTargets <= 0 {
		return errors.New("turret config: reflex_budget.max_targets must be > 0")
	}
	if c.ReflexBudget.Window <= 0 {
		return errors.New("turret config: reflex_budget.window must be > 0")
	}
	if c.PrefixLimiter.Threshold <= 0 {
		return errors.New("turret config: prefix_limiter.threshold must be > 0")
	}
	if c.PrefixLimiter.Window <= 0 {
		return errors.New("turret config: prefix_limiter.window must be > 0")
	}
	return nil
}
