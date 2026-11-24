package rules

import (
	"os"
	"strings"
	"testing"
	"testing/fstest"
)

func TestRepositoryRulesAreValid(t *testing.T) {
	fsys := os.DirFS("../../rules")
	rules, err := LoadDir(fsys)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if len(rules) < 2 {
		t.Fatalf("got %d rules, want >= 2", len(rules))
	}
	mapping, err := LoadMapping(fsys)
	if err != nil {
		t.Fatalf("LoadMapping: %v", err)
	}
	if err := ValidateRules(rules, mapping, fsys); err != nil {
		t.Fatal(err)
	}
}

const (
	idA = "8f0c6c1e-1f6b-4c3e-9a3e-0b5f8e6b2a11"
	idB = "3a2d7e5b-8a8b-4b0e-9a77-6d4f5e1c9b02"
)

const samples = "match: []\nno_match: []\n"

func detRule(id, level, scope, field string) string {
	s := "title: T\nid: " + id + "\nlevel: " + level + "\ndetection:\n  sel:\n    " + field + ": x\n  condition: sel\n"
	if scope != "" {
		s += "custom:\n  scope: " + scope + "\n"
	}
	return s
}

func corrRule(id, target string) string {
	return "title: C\nid: " + id + "\nlevel: low\ncorrelation:\n  type: event_count\n  rules: [" + target + "]\n"
}

var testMapping = map[string]string{"class": "class", "src.ip": "src.ip"}

func TestValidateRules(t *testing.T) {
	cases := []struct {
		name    string
		files   map[string]string
		wantErr string // empty: no error
	}{
		{"valid", map[string]string{
			"a.yml": detRule(idA, "low", "agent", "class"), "a.samples.yml": samples,
			"b.yml": corrRule(idB, idA), "b.samples.yml": samples,
		}, ""},
		{"duplicate id", map[string]string{
			"a.yml": detRule(idA, "low", "", "class"), "a.samples.yml": samples,
			"b.yml": detRule(idA, "low", "", "class"), "b.samples.yml": samples,
		}, "a.yml"},
		{"bad uuid", map[string]string{
			"a.yml": detRule("not-a-uuid", "low", "", "class"), "a.samples.yml": samples,
		}, "uuid"},
		{"bad level", map[string]string{
			"a.yml": detRule(idA, "severe", "", "class"), "a.samples.yml": samples,
		}, "level"},
		{"bad scope", map[string]string{
			"a.yml": detRule(idA, "low", "cloud", "class"), "a.samples.yml": samples,
		}, "scope"},
		{"unmapped field", map[string]string{
			"a.yml": detRule(idA, "low", "", "bogus.field|contains"), "a.samples.yml": samples,
		}, "bogus.field"},
		{"unknown correlation target", map[string]string{
			"b.yml": corrRule(idB, idA), "b.samples.yml": samples,
		}, idA},
		{"missing samples", map[string]string{
			"a.yml": detRule(idA, "low", "", "class"),
		}, "samples"},
		{"samples missing no_match", map[string]string{
			"a.yml": detRule(idA, "low", "", "class"), "a.samples.yml": "match: []\n",
		}, "no_match"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fsys := fstest.MapFS{}
			for k, v := range tc.files {
				fsys[k] = &fstest.MapFile{Data: []byte(v)}
			}
			rs, err := LoadDir(fsys)
			if err != nil {
				t.Fatalf("LoadDir: %v", err)
			}
			err = ValidateRules(rs, testMapping, fsys)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not contain %q", err, tc.wantErr)
			}
			if tc.name == "duplicate id" && !strings.Contains(err.Error(), "b.yml") {
				t.Fatalf("duplicate error must name both paths: %v", err)
			}
		})
	}
}

func TestLoadDirMultiDocAndDefaults(t *testing.T) {
	fsys := fstest.MapFS{"x.yml": &fstest.MapFile{Data: []byte(
		detRule(idA, "low", "", "class") + "---\n" + corrRule(idB, idA))}}
	rs, err := LoadDir(fsys)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 2 || rs[0].Scope != "agent" || len(rs[1].Correlates) != 1 || rs[0].Fields[0] != "class" {
		t.Fatalf("unexpected rules: %+v", rs)
	}
}
