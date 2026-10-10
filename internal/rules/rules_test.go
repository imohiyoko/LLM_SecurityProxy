package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/imohiyoko/LLM_SecurityProxy/internal/detect"
	"github.com/imohiyoko/LLM_SecurityProxy/internal/testsecret"
)

func found(d *detect.Detector, text string) map[string]string {
	out := map[string]string{}
	for _, m := range d.Find(text) {
		out[m.Rule] = text[m.Start:m.End]
	}
	return out
}

func detector(t *testing.T, dirs []string, sel Selection) *detect.Detector {
	t.Helper()
	c, err := Load(dirs)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := c.Compile(sel)
	if err != nil {
		t.Fatal(err)
	}
	return detect.New(compiled)
}

func writeFile(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestBuiltinPositive(t *testing.T) {
	d := detector(t, nil, Selection{})
	cases := []struct{ rule, text, want string }{
		{"builtin/credentials:aws_access_key_id", "key=" + testsecret.AWSAccessKey() + "\n", testsecret.AWSAccessKey()},
		{"builtin/credentials:aws_secret_access_key", "aws_secret_access_key = " + testsecret.AWSSecretKey() + "\n", testsecret.AWSSecretKey()},
		{"builtin/credentials:github_token", "token " + testsecret.GitHubToken(), testsecret.GitHubToken()},
		{"builtin/credentials:anthropic_api_key", "export K=" + testsecret.AnthropicKey(), testsecret.AnthropicKey()},
		{"builtin/credentials:jwt", "Authorization: Bearer " + testsecret.JWT(), testsecret.JWT()},
		{"builtin/credentials:private_key", "x\n" + testsecret.PrivateKey() + "\ny", testsecret.PrivateKey()},
		{"builtin/pii:credit_card", "card: " + testsecret.Card() + ".", testsecret.Card()},
		{"builtin/pii:email", "contact alice@corp.dev now", "alice@corp.dev"},
		{"builtin/generic:assignment", `DB_PASSWORD="s3cr3t-Value!"`, "s3cr3t-Value!"},
	}
	for _, c := range cases {
		t.Run(c.rule, func(t *testing.T) {
			got := found(d, c.text)
			if got[c.rule] != c.want {
				t.Fatalf("got %q, want %q (all: %v)", got[c.rule], c.want, got)
			}
		})
	}
	// The OpenAI rule must not double-match Anthropic keys.
	if _, ok := found(d, testsecret.AnthropicKey())["builtin/credentials:openai_api_key"]; ok {
		t.Error("openai rule matched an anthropic key")
	}
}

func TestBuiltinNegative(t *testing.T) {
	d := detector(t, nil, Selection{})
	for _, text := range []string{
		"git clone git@github.com:owner/repo.git",
		`<img src="icon@2x.png">`,
		"mail user@example.com",
		"created_at: 1700000000000",
		"card 4111 1111 1111 1112",
		"apiKey: process.env.API_KEY",
		"password = getPassword(user)",
		"token: tokenValue",
		`secret: "${SECRET}"`,
		"password: <your-password>",
		"host 10.0.0.1", // network ruleset is off by default
		"already __LLMSP_SECRET_0123456789ab__ masked",
	} {
		if got := found(d, text); len(got) != 0 {
			t.Errorf("%q: unexpected matches %v", text, got)
		}
	}
}

func TestSelection(t *testing.T) {
	d := detector(t, nil, Selection{
		Enable:  []string{"builtin/network"},
		Disable: []string{"builtin/pii:email"},
	})
	got := found(d, "host 10.1.2.3 mail bob@corp.dev card "+testsecret.Card())
	if got["builtin/network:ipv4"] != "10.1.2.3" {
		t.Errorf("ipv4 not enabled: %v", got)
	}
	if _, ok := got["builtin/pii:email"]; ok {
		t.Errorf("email not disabled: %v", got)
	}
	if _, ok := got["builtin/pii:credit_card"]; !ok {
		t.Errorf("disabling one rule disabled its ruleset: %v", got)
	}

	// A single rule can be enabled in a ruleset that is off.
	d = detector(t, nil, Selection{Disable: []string{"builtin/pii"}, Enable: []string{"builtin/pii:credit_card"}})
	got = found(d, "bob@corp.dev "+testsecret.Card())
	if _, ok := got["builtin/pii:email"]; ok || got["builtin/pii:credit_card"] == "" {
		t.Errorf("rule-level enable: %v", got)
	}

	c, _ := Load(nil)
	for _, sel := range []Selection{
		{Enable: []string{"nope"}},
		{Disable: []string{"builtin/pii:nope"}},
	} {
		if _, err := c.Compile(sel); err == nil {
			t.Errorf("%v: expected error for unknown id", sel)
		}
	}
}

func TestUserRuleset(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "hosts.txt", "# internal hosts\nDB.Internal.Example\n\nsearch.internal.example\n")
	writeFile(t, dir, "org.yaml", `
id: org/internal
description: Internal names
rules:
  - id: hosts
    kind: HOST
    values_file: hosts.txt
    case_insensitive: true
  - id: project_code
    kind: PROJECT
    pattern: '\bPRJ-[0-9]{4}\b'
    allow: ['^PRJ-0000$']
  - id: disabled_one
    kind: X
    values: [never-match-me]
    enabled: false
`)
	d := detector(t, []string{dir}, Selection{})
	got := found(d, "connect db.internal.example for PRJ-1234, not PRJ-0000 or never-match-me")
	if got["org/internal:hosts"] != "db.internal.example" {
		t.Errorf("values_file: %v", got)
	}
	if got["org/internal:project_code"] != "PRJ-1234" {
		t.Errorf("pattern: %v", got)
	}
	if _, ok := got["org/internal:disabled_one"]; ok {
		t.Errorf("enabled: false ignored: %v", got)
	}
	if strings.Contains(got["org/internal:project_code"], "0000") {
		t.Errorf("allow ignored: %v", got)
	}
}

func TestUserRulesetOverridesBuiltin(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "pii.yaml", `
id: builtin/pii
rules:
  - id: email
    kind: EMAIL
    pattern: '[a-z]+@corp\.dev'
`)
	c, err := Load([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	if c.Sets["builtin/pii"].Source != filepath.Join(dir, "pii.yaml") {
		t.Fatalf("source: %s", c.Sets["builtin/pii"].Source)
	}
	d := detector(t, []string{dir}, Selection{})
	got := found(d, "bob@corp.dev alice@other.dev "+testsecret.Card())
	if got["builtin/pii:email"] != "bob@corp.dev" {
		t.Errorf("override not used: %v", got)
	}
	if _, ok := got["builtin/pii:credit_card"]; ok {
		t.Errorf("override should replace the whole ruleset: %v", got)
	}
}

func TestInvalidRulesets(t *testing.T) {
	cases := map[string]string{
		"unknown field":     "id: a/b\nrules:\n  - id: r\n    kind: K\n    patern: x\n",
		"bad set id":        "id: Bad ID\nrules: []\n",
		"bad rule id":       "id: a/b\nrules:\n  - id: Bad\n    kind: K\n    pattern: x\n",
		"duplicate rule":    "id: a/b\nrules:\n  - {id: r, kind: K, pattern: x}\n  - {id: r, kind: K, pattern: y}\n",
		"no kind":           "id: a/b\nrules:\n  - {id: r, pattern: x}\n",
		"pattern and value": "id: a/b\nrules:\n  - {id: r, kind: K, pattern: x, values: [y]}\n",
		"neither":           "id: a/b\nrules:\n  - {id: r, kind: K}\n",
		"bad regexp":        "id: a/b\nrules:\n  - {id: r, kind: K, pattern: '(?<=x)'}\n",
		"group range":       "id: a/b\nrules:\n  - {id: r, kind: K, pattern: '(x)', group: 2}\n",
		"unknown validator": "id: a/b\nrules:\n  - {id: r, kind: K, pattern: x, validators: [nope]}\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, dir, "r.yaml", body)
			c, err := Load([]string{dir})
			if err == nil {
				_, err = c.Compile(Selection{})
			}
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}

	dir := t.TempDir()
	writeFile(t, dir, "a.yaml", "id: same/id\nrules: []\n")
	writeFile(t, dir, "b.yml", "id: same/id\nrules: []\n")
	if _, err := Load([]string{dir}); err == nil {
		t.Error("duplicate user ruleset id should fail")
	}
}

// The documented example must stay loadable.
func TestExampleRuleset(t *testing.T) {
	d := detector(t, []string{"../../examples/rules.d"}, Selection{Enable: []string{"example/org:member_number"}})
	text := "db.internal.example " + "deploy-token: " + strings.Repeat("ab12", 4) + " M-123456789012"
	got := found(d, text)
	for _, id := range []string{"example/org:hosts", "example/org:ticket_secret", "example/org:member_number"} {
		if got[id] == "" {
			t.Errorf("%s did not match: %v", id, got)
		}
	}
}

func TestMissingDirIsFine(t *testing.T) {
	if _, err := Load([]string{filepath.Join(t.TempDir(), "absent")}); err != nil {
		t.Fatal(err)
	}
}
