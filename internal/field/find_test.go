package field

import (
	"reflect"
	"testing"
)

// pairs returns name=value for every field found.
func pairs(s string) [][2]string {
	var out [][2]string
	for _, f := range Find(s) {
		out = append(out, [2]string{f.Name, s[f.Start:f.End]})
	}
	return out
}

func TestFind(t *testing.T) {
	cases := []struct {
		in   string
		want [][2]string
	}{
		// JSON
		{`{"userName": "Jane Doe"}`, [][2]string{{"userName", "Jane Doe"}}},
		{`{"userName":"Jane Doe","id":1}`, [][2]string{{"userName", "Jane Doe"}, {"id", "1"}}},
		{`{"displayName": "Jane \"JD\" Doe"}`, [][2]string{{"displayName", `Jane \"JD\" Doe`}}},
		{`{\"userName\":\"Jane Doe\"}`, [][2]string{{"userName", "Jane Doe"}}},
		// YAML / logs
		{"user_name: \"Jane Doe\"\n", [][2]string{{"user_name", "Jane Doe"}}},
		{"user_name: Jane Doe\nrole: admin\n", [][2]string{{"user_name", "Jane Doe"}, {"role", "admin"}}},
		{"  - user_name: Jane Doe   # owner\n", [][2]string{{"user_name", "Jane Doe"}}},
		{"display_name: Doe, Jane\n", [][2]string{{"display_name", "Doe, Jane"}}},
		{"user.name=Jane Doe", [][2]string{{"user.name", "Jane Doe"}}},
		// logfmt / env / shell
		{`level=info user_name="Jane Doe" msg=ok`, [][2]string{{"level", "info"}, {"user_name", "Jane Doe"}, {"msg", "ok"}}},
		{`user_name=Jane level=info`, [][2]string{{"user_name", "Jane"}, {"level", "info"}}},
		{`USER_NAME='Jane Doe'`, [][2]string{{"USER_NAME", "Jane Doe"}}},
		{`user_name=Jane Doe, role=admin`, [][2]string{{"user_name", "Jane Doe"}, {"role", "admin"}}},
		{`userName: Jane;`, [][2]string{{"userName", "Jane"}}},
		{`user_name=Jane;role=admin`, [][2]string{{"user_name", "Jane"}, {"role", "admin"}}},
		{"user_name=Jane\tlevel=info", [][2]string{{"user_name", "Jane"}, {"level", "info"}}},
		// Ruby / PHP / code
		{`:user_name => "Jane Doe"`, [][2]string{{"user_name", "Jane Doe"}}},
		{`'user_name' => 'Jane Doe'`, [][2]string{{"user_name", "Jane Doe"}}},
		{`userName := "Jane Doe"`, [][2]string{{"userName", "Jane Doe"}}},
		{`$user_name = "Jane Doe";`, [][2]string{{"user_name", "Jane Doe"}}},
		{`$this->user_name = 'Jane Doe';`, [][2]string{{"user_name", "Jane Doe"}}},
		{`f(user_name="Jane Doe")`, [][2]string{{"user_name", "Jane Doe"}}},
		{`self.user_name = "Jane Doe"`, [][2]string{{"self.user_name", "Jane Doe"}}},
		{`<a data-user-name="Jane Doe">`, [][2]string{{"data-user-name", "Jane Doe"}}},
		// A field inside another field's quoted value. Unquoted, it runs on to
		// the closing quote: free text after it is masked rather than a
		// second word of the name leaked.
		{`{"msg": "login user_name=Jane Doe ok"}`, [][2]string{{"msg", "login user_name=Jane Doe ok"}, {"user_name", "Jane Doe ok"}}},
		// Python type hint: the annotation ends at =.
		{`def f(user_name: str = "x"):`, [][2]string{{"user_name", "str"}}},
	}
	for _, c := range cases {
		if got := pairs(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("Find(%q)\n got %q\nwant %q", c.in, got, c.want)
		}
	}
}

func TestFindSkips(t *testing.T) {
	for _, in := range []string{
		`user_name: ""`,
		`user_name = ''`,
		`"user_name": "unterminated`,
		"user_name: \"Jane\nDoe\"",
		"user_name:\n  first: x",
		`user_name: {first: x}`,
		`user_name: [a, b]`,
		`user_name: |`,
		`user_name: &anchor`,
		`if user_name == "Jane" {`,
		`std::user_name`,
		`"user_name': 'Jane'`,
		`:user_name": "Jane"`,
	} {
		for _, f := range Find(in) {
			if f.Name == "user_name" {
				t.Errorf("Find(%q) read %q", in, in[f.Start:f.End])
			}
		}
	}
	// A name is never the tail of a longer one.
	for _, in := range []string{`billing.user_name=x`, `my-user_name=x`, `xuser_name=x`} {
		for _, f := range Find(in) {
			if f.Name == "user_name" {
				t.Errorf("Find(%q) matched the tail %q", in, f.Name)
			}
		}
	}
}
