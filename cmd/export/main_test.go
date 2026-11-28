package main

import (
	"bytes"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestNormalizeKey(t *testing.T) {
	for _, tc := range []struct {
		key  string
		leaf bool
		want string
	}{
		{"cve-2021-44228", true, "CVE-2021-44228"},
		{"CVE-2021-44228", true, "CVE-2021-44228"},
		{"GHSA-jfh8-c2jp-5v3q", true, "GHSA-jfh8-c2jp-5v3q"},
		{"Newtonsoft.Json", false, "newtonsoft.json"},
		{"github.com/Foo/Bar", false, "github.com/foo/bar"},
	} {
		if got := normalizeKey(tc.key, tc.leaf); got != tc.want {
			t.Errorf("normalizeKey(%q, %v) = %q, want %q", tc.key, tc.leaf, got, tc.want)
		}
	}
}

func TestMergeLeafCaseFold(t *testing.T) {
	l := leaves{}
	l.mergeLeaf("os/x/pkg/GHSA-AAAA", map[string]any{"A": 1, "Entries": []any{"a"}})
	// Differs from the first only by case: must merge, not coexist.
	l.mergeLeaf("os/x/pkg/ghsa-aaaa", map[string]any{"A": 2, "Entries": []any{"a", "b"}, "B": 3})
	if len(l) != 1 {
		t.Fatalf("got %d leaves, want 1", len(l))
	}
	e := l["os/x/pkg/ghsa-aaaa"]
	if e == nil || e.path != "os/x/pkg/GHSA-AAAA" {
		t.Fatalf("first spelling not kept: %+v", e)
	}
	if e.val["A"] != 1 || e.val["B"] != 3 {
		t.Errorf("unexpected merge: %v", e.val)
	}
	if got := e.val["Entries"].([]any); len(got) != 2 {
		t.Errorf("Entries not unioned: %v", got)
	}
}

func TestValidSegment(t *testing.T) {
	for key, want := range map[string]bool{
		"github.com/foo/bar": true,
		"..":                 false,
		"a/../b":             false,
		"a/./b":              false,
		"":                   false,
		"/abs":               false,
		"a\nb":               false,
	} {
		if got := validSegment(key); got != want {
			t.Errorf("validSegment(%q) = %v, want %v", key, got, want)
		}
	}
}

func TestProtectStringsRoundTrip(t *testing.T) {
	in := map[string]any{
		"Description": "  indented\nsecond line",
		"List":        []any{"\nleading newline\nx", "plain"},
		" k\n":        "v",
	}
	b, err := yaml.Marshal(protectStrings(in))
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := yaml.Unmarshal(b, &out); err != nil {
		t.Fatalf("unparseable output: %v\n%s", err, b)
	}
	if out["Description"] != "  indented\nsecond line" || out[" k\n"] != "v" ||
		out["List"].([]any)[0] != "\nleading newline\nx" {
		t.Errorf("did not round-trip:\n%s\n%v", b, out)
	}
	if !bytes.Contains(b, []byte("plain")) || strings.Contains(string(b), "|") {
		t.Errorf("unexpected block scalar:\n%s", b)
	}
}
