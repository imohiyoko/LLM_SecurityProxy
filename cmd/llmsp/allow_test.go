package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/imohiyoko/LLM_SecurityProxy/internal/allow"
	"github.com/imohiyoko/LLM_SecurityProxy/internal/placeholder"
	"github.com/imohiyoko/LLM_SecurityProxy/internal/testsecret"
)

func TestAllowAddListRm(t *testing.T) {
	cfg, ids := maskedSetup(t)
	path := allow.Path(filepath.Dir(strings.TrimPrefix(cfg, "-config=")))
	add := func(input string, tty bool, args ...string) (string, error) {
		var out bytes.Buffer
		err := allowAdd(append([]string{cfg}, args...), console{in: strings.NewReader(input), out: &out, tty: tty})
		return out.String(), err
	}
	ph := placeholder.Format("NAME", ids["Status Report"])

	// Without a terminal, only with -yes.
	if _, err := add("", false, ph); err == nil || !strings.Contains(err.Error(), "no terminal") {
		t.Fatalf("no tty: %v", err)
	}
	// Declined.
	if out, err := add("n\n", true, ph); err != nil || !strings.Contains(out, "not added") {
		t.Fatalf("declined: %v %s", err, out)
	}
	out, err := add("y\n", true, ph)
	if err != nil || !strings.Contains(out, `"Status Report"`) || !strings.Contains(out, "builtin/pii:name") || !strings.Contains(out, "added") {
		t.Fatalf("add: %v\n%s", err, out)
	}
	if out, _ := add("y\n", true, ids["Status Report"]); !strings.Contains(out, "already allowed") {
		t.Fatalf("again: %s", out)
	}
	// A value not stored, for one profile, without a terminal.
	if _, err := add("", false, "-value", "build-42", "-profile", "nope", "-yes"); err == nil {
		t.Fatal("unknown profile accepted")
	}
	if out, err := add("", false, "-value", "build-42", "-yes"); err != nil || !strings.Contains(out, "warning") {
		t.Fatalf("-yes: %v %s", err, out)
	}
	// A credential needs -force and is never printed.
	tok := ids[testsecret.GitHubToken()]
	if _, err := add("y\n", true, tok); err == nil || !strings.Contains(err.Error(), "-force") {
		t.Fatalf("credential without -force: %v", err)
	}
	if _, err := add("y\n", true, "-value", testsecret.AWSAccessKey()); err == nil || !strings.Contains(err.Error(), "-force") {
		t.Fatalf("unstored credential without -force: %v", err)
	}
	out, err = add("y\n", true, "-force", tok)
	if err != nil || strings.Contains(out, testsecret.GitHubToken()) || !strings.Contains(out, "not shown") {
		t.Fatalf("credential -force: %v\n%s", err, out)
	}

	entries, err := allow.Load(path)
	if err != nil || len(entries) != 3 || entries[0].Value != "Status Report" || entries[0].Rule != "builtin/pii:name" ||
		entries[0].Unconfirmed || !entries[1].Unconfirmed {
		t.Fatalf("entries: %+v %v", entries, err)
	}

	var list bytes.Buffer
	if err := allowList([]string{cfg}, &list); err != nil || !strings.Contains(list.String(), "build-42") || !strings.Contains(list.String(), "(-yes)") ||
		strings.Contains(list.String(), testsecret.GitHubToken()) {
		t.Fatalf("list: %v\n%s", err, list.String())
	}
	var masked bytes.Buffer
	if err := maskedList([]string{cfg, "-kind", "name"}, &masked); err != nil || !strings.Contains(masked.String(), "[allowed]") {
		t.Fatalf("masked list: %v\n%s", err, masked.String())
	}

	var rm bytes.Buffer
	if err := allowRm([]string{cfg, "-value", "build-42"}, &rm); err != nil {
		t.Fatal(err)
	}
	if err := allowRm([]string{cfg, "1"}, &rm); err != nil {
		t.Fatal(err)
	}
	if err := allowRm([]string{cfg, "5"}, &rm); err == nil {
		t.Fatal("bad number accepted")
	}
	entries, _ = allow.Load(path)
	if len(entries) != 1 || entries[0].Value != testsecret.GitHubToken() {
		t.Fatalf("after rm: %+v", entries)
	}
}
