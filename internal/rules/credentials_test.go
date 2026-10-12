package rules

import (
	"strings"
	"testing"
)

// Fake values are assembled at run time so that the repository never contains
// a literal that looks like a real secret to scanners.

func TestURLCredentials(t *testing.T) {
	d := detector(t, nil, Selection{})
	const rule = "builtin/credentials:url_credentials"
	pw := "FakePw" + "Value9x"
	for _, text := range []string{
		"postgres://app:" + pw + "@db:5432/app",
		"DATABASE_URL=postgres://app:" + pw + "@db:5432/app",
		"redis://:" + pw + "@cache:6379/0",
		"amqp://guest:" + pw + "@localhost/",
		`"url": "mysql://root:` + pw + `@127.0.0.1:3306/x"`,
		"mongodb+srv://u:" + pw + "@cluster0.mongodb.example.net/db",
		"postgres://app:" + pw + "@db",
		"postgres://app:" + pw + "@db?sslmode=require",
		`connect("postgres://app:` + pw + `@db")`,
		"postgres://app:" + pw + "@db/app?next=x@y",
	} {
		if got := found(d, text)[rule]; got != pw {
			t.Errorf("%q: got %q, want %q", text, got, pw)
		}
	}
	// Passwords with characters that should have been percent-encoded are
	// still masked whole: the password runs to the last @ before the host.
	for _, p := range []string{
		"Fa@ke" + "Pw99",
		"Fa@ke@" + "Pw99",
		"Fa/ke" + "Pw99",
		"Fa/k@e" + "Pw99",
		"Fa%40ke" + "Pw99",
	} {
		for _, text := range []string{
			"postgres://app:" + p + "@db:5432/app",
			"redis://:" + p + "@cache",
			"DATABASE_URL=mysql://root:" + p + "@10.0.0.5/x other@text",
		} {
			if got := found(d, text)[rule]; got != p {
				t.Errorf("%q: got %q, want %q", text, got, p)
			}
		}
	}
	for _, text := range []string{
		"https://example.com/path?q=a:b",
		"https://host:8443/path",
		"git clone git@github.com:owner/repo.git",
		"ssh://git@github.com/owner/repo.git",
		"postgres://app:${DB_PASSWORD}@db/app",
		"postgres://app:$DB_PASSWORD@db/app",
		"postgres://app:{{ db_password }}@db/app",
		"postgres://user:password@localhost/db",
		"postgres://user:<password>@localhost/db",
		"postgres://user:****@localhost/db",
		"redis://:__LLMSP_SECRET_0123456789ab__@cache",
		"https://host/path@x",
		"https://host:8443/path@x",
		"https://host:8443/a?next=http://u@x",
	} {
		if got, ok := found(d, text)[rule]; ok {
			t.Errorf("%q: unexpected match %q", text, got)
		}
	}
}

func TestPGPPrivateKey(t *testing.T) {
	d := detector(t, nil, Selection{})
	key := "-----BEGIN " + "PGP PRIVATE KEY BLOCK-----\n\nlQOYBGfakefake\nZmFrZWZha2U=\n=AbCd\n-----END " + "PGP PRIVATE KEY BLOCK-----"
	if got := found(d, "x\n"+key+"\ny")["builtin/credentials:private_key"]; got != key {
		t.Errorf("got %q", got)
	}
	// Public key blocks are not secrets.
	pub := "-----BEGIN " + "PGP PUBLIC KEY BLOCK-----\nmQINBGfake\n-----END " + "PGP PUBLIC KEY BLOCK-----"
	if got := found(d, pub); len(got) != 0 {
		t.Errorf("public key matched: %v", got)
	}
}

func TestVendorTokens(t *testing.T) {
	d := detector(t, nil, Selection{})
	cases := []struct{ rule, value string }{
		{"builtin/credentials:slack_token", "xapp-" + "1-A0FAKE0001-1234567890-" + strings.Repeat("ab12", 8)},
		{"builtin/credentials:slack_token", "xox" + "b-1234567890-" + strings.Repeat("Ab1", 8)},
		{"builtin/credentials:stripe_key", "sk_" + "live_" + strings.Repeat("Fa1e", 6)},
		{"builtin/credentials:stripe_key", "rk_" + "live_" + strings.Repeat("Fa1e", 6)},
		{"builtin/credentials:gitlab_token", "glpat" + "-" + strings.Repeat("Fa1e", 5)},
		{"builtin/credentials:npm_token", "npm" + "_" + strings.Repeat("Fa1e", 9)},
	}
	for _, c := range cases {
		text := "TOKEN_VALUE " + c.value + "\n"
		if got := found(d, text)[c.rule]; got != c.value {
			t.Errorf("%s: got %q, want %q (all: %v)", c.rule, got, c.value, found(d, text))
		}
	}
	for _, text := range []string{
		"sk_" + "test_" + strings.Repeat("Fa1e", 6), // test-mode keys are not covered
		"npm_" + "package_name",
		"glpat" + "-short",
	} {
		if got := found(d, text); len(got) != 0 {
			t.Errorf("%q: unexpected matches %v", text, got)
		}
	}
}
