package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/imohiyoko/LLM_SecurityProxy/internal/placeholder"
	"github.com/imohiyoko/LLM_SecurityProxy/internal/store"
	"github.com/imohiyoko/LLM_SecurityProxy/internal/testsecret"
)

// maskedSetup writes a config whose data directory holds a few values, and
// returns the -config argument and the store's IDs by value.
func maskedSetup(t *testing.T) (string, map[string]string) {
	t.Helper()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfg, []byte("listen: 127.0.0.1:9001\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ids := map[string]string{}
	for _, v := range []struct{ kind, value, rule, profile string }{
		{"NAME", "Status Report", "builtin/pii:name", "claude"},
		{"EMAIL", "bob@corp.dev", "builtin/pii:email", "codex"},
		{"GITHUB_TOKEN", testsecret.GitHubToken(), "builtin/credentials:github-token", "claude"},
		{"GITHUB_TOKEN", testsecret.GitHubToken() + "x", "", ""}, // stored before origins were
	} {
		id, _, err := st.PutFrom(v.kind, v.value, store.Origin{Rule: v.rule, Profile: v.profile})
		if err != nil {
			t.Fatal(err)
		}
		ids[v.value] = id
	}
	return "-config=" + cfg, ids
}

func TestMaskedList(t *testing.T) {
	cfg, ids := maskedSetup(t)
	run := func(args ...string) string {
		t.Helper()
		var out bytes.Buffer
		if err := maskedList(append([]string{cfg}, args...), &out); err != nil {
			t.Fatal(err)
		}
		return out.String()
	}

	out := run()
	if strings.Contains(out, "Status Report") || !strings.Contains(out, `"Sta"… (13 chars)`) {
		t.Errorf("value not shortened:\n%s", out)
	}
	if strings.Contains(out, testsecret.GitHubToken()) || strings.Count(out, "(hidden: credential") != 2 {
		t.Errorf("credential not hidden:\n%s", out)
	}
	if !strings.Contains(out, placeholder.Format("NAME", ids["Status Report"])) || !strings.Contains(out, "builtin/pii:name") {
		t.Errorf("placeholder or rule missing:\n%s", out)
	}
	// Newest first.
	email := strings.Index(out, placeholder.Format("EMAIL", ids["bob@corp.dev"]))
	name := strings.Index(out, placeholder.Format("NAME", ids["Status Report"]))
	if email < 0 || name < 0 || email > name {
		t.Errorf("not newest first:\n%s", out)
	}

	out = run("-show", "-rule", "builtin/pii")
	if !strings.Contains(out, `"Status Report"`) || !strings.Contains(out, `"bob@corp.dev"`) || strings.Contains(out, "GITHUB") {
		t.Errorf("-show -rule:\n%s", out)
	}
	out = run("-show", "-profile", "codex")
	if !strings.Contains(out, "bob@corp.dev") || strings.Contains(out, "Status") {
		t.Errorf("-profile:\n%s", out)
	}
	out = run("-show", "-kind", "name", "-grep", "REPORT")
	if !strings.Contains(out, "Status Report") || strings.Contains(out, "bob") {
		t.Errorf("-kind -grep:\n%s", out)
	}
	out = run("-show-secrets", "-show", "-kind", "github_token")
	if !strings.Contains(out, testsecret.GitHubToken()) {
		t.Errorf("-show-secrets:\n%s", out)
	}
	out = run("-n", "1")
	if !strings.Contains(out, "(1 of 4 shown") {
		t.Errorf("-n:\n%s", out)
	}
	if out := run("-since", "1d"); strings.Count(out, "__LLMSP_") != 4 {
		t.Errorf("-since 1d:\n%s", out)
	}
}

func TestMaskedShow(t *testing.T) {
	cfg, ids := maskedSetup(t)
	show := func(args ...string) (string, error) {
		var out bytes.Buffer
		err := maskedShow(append([]string{cfg}, args...), &out)
		return out.String(), err
	}
	out, err := show("see " + placeholder.Format("NAME", ids["Status Report"]) + " here")
	if err != nil || !strings.Contains(out, `"Status Report"`) || !strings.Contains(out, "builtin/pii:name") || !strings.Contains(out, "claude") {
		t.Errorf("by placeholder: %v\n%s", err, out)
	}
	out, err = show(ids[testsecret.GitHubToken()])
	if err != nil || strings.Contains(out, testsecret.GitHubToken()) || !strings.Contains(out, "hidden") {
		t.Errorf("credential by id: %v\n%s", err, out)
	}
	out, err = show("-show-secrets", ids[testsecret.GitHubToken()])
	if err != nil || !strings.Contains(out, testsecret.GitHubToken()) {
		t.Errorf("-show-secrets: %v\n%s", err, out)
	}
	if _, err := show("0123456789ab"); err == nil || !strings.Contains(err.Error(), "not in the store") {
		t.Errorf("unknown id: %v", err)
	}
	if _, err := show("nonsense"); err == nil {
		t.Error("bad argument accepted")
	}
}

// Rows without a rule are hidden by the built-in credential kinds even when
// a user ruleset replaces builtin/credentials without those rules.
func TestMaskedOldRowsHiddenWithReplacedRuleset(t *testing.T) {
	cfg, ids := maskedSetup(t)
	dir := filepath.Dir(strings.TrimPrefix(cfg, "-config="))
	if err := os.MkdirAll(filepath.Join(dir, "rules.d"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "rules.d", "creds.yaml"), []byte(`id: builtin/credentials
rules:
  - id: only
    kind: OTHER_TOKEN
    pattern: 'tok_[a-z]{20}'
`), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := maskedShow([]string{cfg, ids[testsecret.GitHubToken()+"x"]}, &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), testsecret.GitHubToken()) || !strings.Contains(out.String(), "hidden") {
		t.Fatalf("old row shown:\n%s", out.String())
	}
}

// A KNOWN record without a rule, as an older llmsp stored the JSON-escaped
// form of a value, is hidden when the value it stands for is a credential
// (or cannot be found), and shown otherwise.
func TestMaskedOldEscapedForms(t *testing.T) {
	cfg, _ := maskedSetup(t)
	dir := filepath.Dir(strings.TrimPrefix(cfg, "-config="))
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	cred, mail := `to"k`+testsecret.Passphrase(), `"amy"@corp.dev`
	esc := func(v string) string { return strings.ReplaceAll(v, `"`, `\"`) }
	ids := map[string]string{}
	for _, v := range []struct{ kind, value string }{
		{"GITHUB_TOKEN", cred}, {"EMAIL", mail},
		{"KNOWN", esc(cred)}, {"KNOWN", esc(mail)}, {"KNOWN", `orphan\"` + testsecret.Passphrase()},
	} {
		id, _, err := st.Put(v.kind, v.value)
		if err != nil {
			t.Fatal(err)
		}
		ids[v.value] = id
	}
	st.Close()
	show := func(v string) string {
		t.Helper()
		var out bytes.Buffer
		if err := maskedShow([]string{cfg, ids[v]}, &out); err != nil {
			t.Fatal(err)
		}
		return out.String()
	}
	if out := show(esc(cred)); strings.Contains(out, testsecret.Passphrase()) {
		t.Errorf("escaped credential shown:\n%s", out)
	}
	if out := show(`orphan\"` + testsecret.Passphrase()); strings.Contains(out, testsecret.Passphrase()) {
		t.Errorf("orphan escaped form shown:\n%s", out)
	}
	if out := show(esc(mail)); !strings.Contains(out, "amy") {
		t.Errorf("escaped e-mail hidden:\n%s", out)
	}
}

// Inspecting an empty data directory creates no key.
func TestMaskedNoStore(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfg, []byte("listen: 127.0.0.1:9001\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := maskedList([]string{"-config=" + cfg}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "nothing masked yet") {
		t.Fatalf("err %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "master.key")); !os.IsNotExist(err) {
		t.Fatalf("key created: %v", err)
	}
}
