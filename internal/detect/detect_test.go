package detect

import (
	"testing"

	"github.com/imohiyoko/LLM_SecurityProxy/internal/testsecret"
)

func found(t *testing.T, d *Detector, text string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, m := range d.Find(text) {
		out[m.Kind] = text[m.Start:m.End]
	}
	return out
}

func TestBuiltinPositive(t *testing.T) {
	d, err := New(nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct{ kind, text, want string }{
		{"AWS_ACCESS_KEY", "key=" + testsecret.AWSAccessKey() + "\n", testsecret.AWSAccessKey()},
		{"AWS_SECRET_KEY", "aws_secret_access_key = " + testsecret.AWSSecretKey() + "\n", testsecret.AWSSecretKey()},
		{"GITHUB_TOKEN", "token " + testsecret.GitHubToken(), testsecret.GitHubToken()},
		{"ANTHROPIC_KEY", "export K=" + testsecret.AnthropicKey(), testsecret.AnthropicKey()},
		{"JWT", "Authorization: Bearer " + testsecret.JWT(), testsecret.JWT()},
		{"PRIVATE_KEY", "x\n" + testsecret.PrivateKey() + "\ny", testsecret.PrivateKey()},
		{"CREDIT_CARD", "card: " + testsecret.Card() + ".", testsecret.Card()},
		{"EMAIL", "contact alice@corp.invalid-tld.dev now", "alice@corp.invalid-tld.dev"},
		{"SECRET", `DB_PASSWORD="s3cr3t-Value!"`, "s3cr3t-Value!"},
	}
	for _, c := range cases {
		t.Run(c.kind, func(t *testing.T) {
			got := found(t, d, c.text)
			if got[c.kind] != c.want {
				t.Fatalf("kind %s: got %q, want %q (all: %v)", c.kind, got[c.kind], c.want, got)
			}
		})
	}
}

func TestBuiltinNegative(t *testing.T) {
	d, err := New(nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{
		"git clone git@github.com:owner/repo.git",
		`<img src="icon@2x.png">`,
		"mail user@example.com",
		"created_at: 1700000000000",
		"apiKey: process.env.API_KEY",
		"password = getPassword(user)",
		"token: tokenValue",
		`secret: "${SECRET}"`,
		"password: <your-password>",
		"version 10.0.0.1",
		"already __LLMSP_SECRET_0123456789ab__ masked",
	} {
		if got := found(t, d, text); len(got) != 0 {
			t.Errorf("%q: unexpected matches %v", text, got)
		}
	}
}

func TestOptionalAndDisable(t *testing.T) {
	d, err := New([]string{"ipv4"}, []string{"email"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := found(t, d, "host 10.1.2.3 mail bob@corp.dev")
	if got["IPV4"] != "10.1.2.3" || got["EMAIL"] != "" {
		t.Fatalf("got %v", got)
	}
	if _, err := New([]string{"nope"}, nil, nil); err == nil {
		t.Fatal("unknown rule should fail")
	}
}

func TestDictionary(t *testing.T) {
	r, err := DictionaryRule("dict", "HOST", []string{"db.internal.example", "db"}, true)
	if err != nil {
		t.Fatal(err)
	}
	d, _ := New(nil, []string{"email"}, []Rule{r})
	got := found(t, d, "connect to DB.Internal.Example:5432")
	if got["HOST"] != "DB.Internal.Example" {
		t.Fatalf("got %v", got)
	}
}
