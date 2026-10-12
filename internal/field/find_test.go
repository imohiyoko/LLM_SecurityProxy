package field

import (
	"reflect"
	"strings"
	"testing"
	"time"
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
		// A type annotation is not a value; the default after it is a field
		// of its own.
		{`def f(user_name: str = "x"):`, [][2]string{{"str", "x"}}},
		// A quote before the name that does not close it belongs to an
		// enclosing string.
		{`docker run -e "FULL_NAME=Jane Doe" img`, [][2]string{{"FULL_NAME", "Jane Doe"}}},
		{`curl -d "first_name=Jane&last_name=Doe"`, [][2]string{{"first_name", "Jane"}, {"last_name", "Doe"}}},
		// Apostrophes inside a word, doubled quotes.
		{"last_name: O'Brien\n", [][2]string{{"last_name", "O'Brien"}}},
		{"last_name: O''Brien\n", [][2]string{{"last_name", "O''Brien"}}},
		{`last_name = 'O''Brien'`, [][2]string{{"last_name", "O''Brien"}}},
		{`last_name='O\'Brien'`, [][2]string{{"last_name", `O\'Brien`}}},
		// An empty value before another field (go-logfmt).
		{`user_name= display_name="Jane Doe"`, [][2]string{{"display_name", "Jane Doe"}}},
		{`user_name="" display_name="Jane Doe"`, [][2]string{{"display_name", "Jane Doe"}}},
		// String prefixes.
		{`user_name = u'Jane'`, [][2]string{{"user_name", "Jane"}}},
		{`user_name = f"Jane {x}"`, [][2]string{{"user_name", "Jane {x}"}}},
		// Balanced brackets stay in an unquoted value.
		{"display_name: Jane (JD) Doe\n", [][2]string{{"display_name", "Jane (JD) Doe"}}},
		{`f(user_name=Jane)`, [][2]string{{"user_name", "Jane"}}},
		// Names that are not ASCII identifiers.
		// The last word of a label is read as a name of its own as well.
		{"Full Name: Jane Doe\n", [][2]string{{"Name", "Jane Doe"}, {"Full Name", "Jane Doe"}}},
		{`app --user-name=Jane`, [][2]string{{"user-name", "Jane"}}},
		{`$row['last_name'] = 'Doe';`, [][2]string{{"last_name", "Doe"}}},
		{`user["first_name"] = "Jane"`, [][2]string{{"first_name", "Jane"}}},
		{`<ns:first_name> Jane </ns:first_name>`, [][2]string{{"ns", "first_name"}, {"first_name", "Jane"}, {"ns", "first_name"}}},
		{"氏名：山田太郎\n", [][2]string{{"氏名", "山田太郎"}}},
		{"氏名: 山田 太郎\n", [][2]string{{"氏名", "山田 太郎"}}},
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
		// Code, not data.
		`user_name = get_name(user)`,
		`user_name = users[0]`,
		`user_name: ${USER_NAME}`,
		`user_name = $name`,
		`full_name = first + " " + last`,
		`userName: string;`,
		`def f(user_name: Optional[str] = None):`,
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

// A long line of fields is scanned in linear time, whatever the quoting:
// doubling the input must not much more than double the time.
func TestFindLongLineIsLinear(t *testing.T) {
	timed := func(line string) time.Duration {
		start := time.Now()
		Find(line)
		return time.Since(start)
	}
	for _, unit := range []string{`\"user_name\":\"Jane Doe\",`, `user_name=Jane Doe, `, `"user_name": "Jane", `} {
		if n := len(Find(strings.Repeat(unit, 100))); n != 100 {
			t.Fatalf("%q: found %d fields", unit, n)
		}
		small, large := timed(strings.Repeat(unit, 1000)), timed(strings.Repeat(unit, 4000))
		if large > 8*small+10*time.Millisecond {
			t.Errorf("%q: 4x input took %v vs %v", unit, large, small)
		}
	}
}
