package rules

import (
	"strings"
	"testing"
)

// fakeValue is assembled at run time; see package testsecret.
func fakeValue() string { return "Fake" + "PwValue9x" }

func TestGenericForms(t *testing.T) {
	d := detector(t, nil, Selection{})
	v := fakeValue()
	b64 := "dXNlcjpw" + "YXNzd29yZA=="
	cases := []struct{ rule, text, want string }{
		// Separators and key styles (#13).
		{"builtin/generic:assignment", `password := "<v>"`, v},
		{"builtin/generic:assignment", `'password' => '<v>',`, v},
		{"builtin/generic:assignment", `:password => "<v>"`, v},
		{"builtin/generic:assignment", `password = "<v>"`, v},
		{"builtin/generic:assignment", `"password": "<v>"`, v},
		{"builtin/generic:xml_element", `<password><v></password>`, v},
		{"builtin/generic:xml_element", "<db.password type=\"x\">\n  <v>\n</db.password>", v},
		{"builtin/generic:php_define", `define( 'DB_PASSWORD', '<v>' );`, v},
		{"builtin/generic:php_define", `define("AUTH_TOKEN","<v>")`, v},

		// Names (#14).
		{"builtin/generic:assignment", "HF_TOKEN=<v>", v},
		{"builtin/generic:assignment", "npmToken: <v>", v},
		{"builtin/generic:assignment", "refresh_token=<v>", v},
		{"builtin/generic:assignment", `"SessionToken": "<v>"`, v},
		{"builtin/generic:assignment", "DB_PASS=<v>", v},
		{"builtin/generic:assignment", "dbPass: <v>", v},
		{"builtin/generic:assignment", "pass=<v>", v},
		{"builtin/generic:assignment", "passphrase=<v>", v},
		{"builtin/generic:assignment", "auth_token_value=<v>", v},
		{"builtin/generic:assignment", "refresh_token_v2=<v>", v},
		{"builtin/generic:assignment", "sessionTokenSecret: <v>", v},
		{"builtin/generic:xml_element", "<auth_token_value><v></auth_token_value>", v},
		{"builtin/generic:php_define", `define('AUTH_TOKEN_VALUE', '<v>')`, v},
		{"builtin/credentials:authorization", "Authorization: Bearer <v>", v},
		{"builtin/credentials:authorization", `curl -H 'Authorization: Basic ` + b64 + `'`, b64},
		{"builtin/credentials:authorization", `"authorization": "token <v>"`, v},

		// Symbols in values (#15).
		{"builtin/generic:assignment", "password=Fake{Pw}Value9", "Fake{Pw}Value9"},
		{"builtin/generic:assignment", "password=Fake(Pw)Value9", "Fake(Pw)Value9"},
		{"builtin/generic:assignment", "password=@FakePwValue9", "@FakePwValue9"},
		{"builtin/generic:assignment", "password=$FakePwValue9", "$FakePwValue9"},
		{"builtin/generic:assignment", "password=Fake.PwValue", "Fake.PwValue"},
		{"builtin/generic:assignment", "password=Fake,PwValue9", "Fake,PwValue9"},
		{"builtin/generic:assignment", `password="FakePwVa;lue9xyz"`, "FakePwVa;lue9xyz"},
		{"builtin/generic:assignment", "PASSWORD=" + v + ";", v},
		{"builtin/generic:assignment", "{password: " + v + ", user: bob}", v},
		{"builtin/generic:assignment", "password=Pa55w(rd)", "Pa55w(rd)"},
		{"builtin/generic:assignment", "password=$uperKey99", "$uperKey99"},
		{"builtin/generic:assignment", "password=@dminPass1", "@dminPass1"},
		{"builtin/generic:assignment", "password=MYSECRETPASS", "MYSECRETPASS"},
		{"builtin/generic:assignment", "password=TOKENAUTHPASS", "TOKENAUTHPASS"},
		{"builtin/generic:assignment", "password=83749201", "83749201"},
		{"builtin/generic:assignment", "auth_token=83749201", "83749201"},

		// A skipped value does not swallow the next assignment.
		{"builtin/generic:assignment", "password=__LLMSP_SECRET_" + "0123456789ab" + "__;api_key=<v>", v},
		{"builtin/generic:assignment", "password=$DB_PASSWORD,api_key=<v>", v},
		{"builtin/generic:assignment", "password=changeme;secret=<v>", v},

		// Connection strings end the value at ';'.
		{"builtin/generic:assignment", "Server=db;Password=<v>;Database=prod;User Id=sa", v},
		{"builtin/generic:assignment", "Server=db;Password=<v>;Encrypt=true", v},
	}
	for _, c := range cases {
		text := strings.ReplaceAll(c.text, "<v>", v)
		t.Run(text, func(t *testing.T) {
			got := found(d, text)
			if got[c.rule] != c.want {
				t.Fatalf("got %q, want %q (all: %v)", got[c.rule], c.want, got)
			}
		})
	}
}

func TestGenericNegative(t *testing.T) {
	d := detector(t, nil, Selection{})
	for _, text := range []string{
		"password = getPassword(user, realm)",
		`password = os.getenv("DB_PASSWORD")`,
		`password: "${DB_PASSWORD}"`,
		`password: "#{db_password}"`,
		"password: {{.Values.dbPassword}}",
		"password=$DB_PASSWORD",
		"'password' => $password,",
		"'password' => $this->password,",
		"password = @dbPassword",
		"password=%DB_PASSWORD%",
		"secret = config.db.password",
		"apiKey = this.apiKey",
		"password = user.password",
		"<password>${db.password}</password>",
		"bypass=somevalue123",
		"passage: somewhere-far",
		"pass_through: somevalue123",
		"token: tokenValue",
		"Authorization: Bearer $TOKEN",
		"password: changeme",

		// Code that passes a variable or template on.
		"client = OpenAI(api_key=API_KEY)",
		"client = OpenAI(api_key=api_key)",
		`f"password={self.password}"`,
		`"password=%(password)s" % params`,
		"password={password}",

		// Token counts and pagination cursors.
		`"prompt_token_count": 12345678`,
		`"total_token_count": 123456789`,
		`{"prompt_token_count":123456789}`,
		"<prompt_token_count>123456789</prompt_token_count>",
		`define('PROMPT_TOKEN_COUNT', '123456789')`,
		"password=DB_PASSWORD",
		"password=PASSWORD_HASH",
		"api_key=API_KEY",
		"password: PASSWORD",
		`"next_page_token": "<v>"`,
		"nextPageToken: <v>",
		"page_token=<v>",
	} {
		text = strings.ReplaceAll(text, "<v>", fakeValue())
		if got := found(d, text); len(got) != 0 {
			t.Errorf("%q: unexpected matches %v", text, got)
		}
	}
}
