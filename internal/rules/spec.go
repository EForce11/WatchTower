// Package rules loads Sigma-compatible detection rules and structurally
// validates them. It does not match events; the engine arrives in Phase 2.
package rules

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Rule is the structural view of one rule document.
type Rule struct {
	Path       string // relative to the rules root FS
	Title      string
	ID         string
	Level      string
	Scope      string // custom.scope, default "agent"
	Fields     []string
	Correlates []string
}

const (
	mappingFile   = "wes-mapping.yaml"
	samplesSuffix = ".samples.yml"
)

var (
	uuidRE      = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	validLevels = map[string]bool{"informational": true, "low": true, "medium": true, "high": true, "critical": true}
	validScopes = map[string]bool{"agent": true, "core": true}
)

type rawRule struct {
	Title     string                 `yaml:"title"`
	ID        string                 `yaml:"id"`
	Level     string                 `yaml:"level"`
	Detection map[string]interface{} `yaml:"detection"`
	Corr      *struct {
		Rules []string `yaml:"rules"`
	} `yaml:"correlation"`
	Custom struct {
		Scope string `yaml:"scope"`
	} `yaml:"custom"`
}

// LoadMapping reads wes-mapping.yaml (Sigma field name -> WES field path).
func LoadMapping(fsys fs.FS) (map[string]string, error) {
	b, err := fs.ReadFile(fsys, mappingFile)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", mappingFile, err)
	}
	m := map[string]string{}
	if err := yaml.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("parse %s: %w", mappingFile, err)
	}
	return m, nil
}

// LoadDir parses every *.yml (except *.samples.yml) under fsys. Multi-document
// files yield one Rule per document. Parse problems for all files are joined.
func LoadDir(fsys fs.FS) ([]Rule, error) {
	var out []Rule
	var errs []error
	walkErr := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(p, ".yaml") && p != mappingFile {
			errs = append(errs, fmt.Errorf("%s: rule files must use .yml", p))
			return nil
		}
		if d.IsDir() || !strings.HasSuffix(p, ".yml") || strings.HasSuffix(p, samplesSuffix) {
			return nil
		}
		b, err := fs.ReadFile(fsys, p)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", p, err))
			return nil
		}
		dec := yaml.NewDecoder(bytes.NewReader(b))
		for i := 0; ; i++ {
			var raw rawRule
			err := dec.Decode(&raw)
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: document %d: %w", p, i, err))
				break
			}
			r := Rule{Path: p, Title: raw.Title, ID: raw.ID, Level: raw.Level, Scope: raw.Custom.Scope}
			if r.Scope == "" {
				r.Scope = "agent"
			}
			switch {
			case raw.Detection != nil && raw.Corr != nil:
				errs = append(errs, fmt.Errorf("%s: document %d: has both detection and correlation", p, i))
				continue
			case raw.Detection != nil:
				r.Fields = detectionFields(raw.Detection)
			case raw.Corr != nil:
				r.Correlates = raw.Corr.Rules
			default:
				errs = append(errs, fmt.Errorf("%s: document %d: neither detection nor correlation", p, i))
				continue
			}
			out = append(out, r)
		}
		return nil
	})
	if walkErr != nil {
		errs = append(errs, walkErr)
	}
	return out, errors.Join(errs...)
}

func detectionFields(det map[string]interface{}) []string {
	set := map[string]bool{}
	add := func(v interface{}) {
		if m, ok := v.(map[string]interface{}); ok {
			for k := range m {
				name, _, _ := strings.Cut(k, "|")
				set[name] = true
			}
		}
	}
	for k, v := range det {
		if k == "condition" {
			continue
		}
		if list, ok := v.([]interface{}); ok {
			for _, e := range list {
				add(e)
			}
			continue
		}
		add(v)
	}
	fields := make([]string, 0, len(set))
	for f := range set {
		fields = append(fields, f)
	}
	sort.Strings(fields)
	return fields
}

// ValidateRules checks every rule structurally and returns all problems joined.
// fsys is the same rules root passed to LoadDir.
func ValidateRules(rules []Rule, mapping map[string]string, fsys fs.FS) error {
	var errs []error
	bad := func(r *Rule, format string, a ...any) {
		errs = append(errs, fmt.Errorf("%s: %s", r.Path, fmt.Sprintf(format, a...)))
	}
	ids := map[string]string{}
	for i := range rules {
		r := &rules[i]
		if !uuidRE.MatchString(r.ID) {
			bad(r, "id %q is not a uuid", r.ID)
		} else if prev, dup := ids[r.ID]; dup {
			bad(r, "duplicate id %s (also in %s)", r.ID, prev)
		} else {
			ids[r.ID] = r.Path
		}
	}
	checkedSamples := map[string]bool{}
	for i := range rules {
		r := &rules[i]
		if !validLevels[r.Level] {
			bad(r, "invalid level %q", r.Level)
		}
		if !validScopes[r.Scope] {
			bad(r, "invalid custom.scope %q (want agent or core)", r.Scope)
		}
		for _, f := range r.Fields {
			if _, ok := mapping[f]; !ok {
				bad(r, "field %q is not in %s", f, mappingFile)
			}
		}
		for _, c := range r.Correlates {
			if _, ok := ids[c]; !ok {
				bad(r, "correlation references unknown rule id %q", c)
			}
		}
		if !checkedSamples[r.Path] {
			checkedSamples[r.Path] = true
			if err := checkSamples(fsys, r.Path); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", r.Path, err))
			}
		}
	}
	return errors.Join(errs...)
}

func checkSamples(fsys fs.FS, rulePath string) error {
	sp := strings.TrimSuffix(rulePath, path.Ext(rulePath)) + samplesSuffix
	b, err := fs.ReadFile(fsys, sp)
	if err != nil {
		return fmt.Errorf("samples file %s: %w", sp, err)
	}
	var doc map[string]interface{}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return fmt.Errorf("samples file %s: %w", sp, err)
	}
	for _, key := range []string{"match", "no_match"} {
		v, ok := doc[key]
		if !ok {
			return fmt.Errorf("samples file %s: missing %q", sp, key)
		}
		if _, isList := v.([]interface{}); !isList && v != nil {
			return fmt.Errorf("samples file %s: %q must be a list", sp, key)
		}
	}
	return nil
}
