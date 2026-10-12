package field

import (
	"regexp"
	"strings"
)

// Field is a value assigned to a named field.
type Field struct {
	// Name is the field name as written, without quotes.
	Name string
	// Start and End are the byte offsets of the value, without its quotes.
	Start, End int
}

// keyPattern matches a field name and its separator, but not the value, so
// that a field written inside another field's value is found too. The name is
// optionally quoted ("name", 'name', \"name\") or a Ruby symbol (:name); the
// separator is :, =, := or =>. The name may not follow a letter, digit or one
// of _ . -, so that it is never the tail of a longer name.
var keyPattern = regexp.MustCompile(`(?:^|[^\w.-])(\\?["']|:)?([A-Za-z_][\w.-]*)(\\?["'])?[ \t]*(:=|=>|=|:)[ \t]*`)

// nextKey is what may follow a soft stop in an unquoted value for the value to
// end there: another field name and separator.
var nextKey = regexp.MustCompile(`^[ \t]*[A-Za-z_][\w.-]*[ \t]*(?::=|=>|=|:[ \t])`)

// Find returns every field assignment in s whose value can be read:
//
//	"userName": "Jane Doe"            JSON (\" escapes allowed)
//	user_name: "Jane Doe"             YAML, logs
//	user_name: Jane Doe               unquoted, see below
//	user_name="Jane Doe"              logfmt, env, Python, HTML attributes
//	USER_NAME='Jane Doe'              shell
//	:user_name => "Jane Doe"          Ruby
//	'user_name' => 'Jane Doe'         PHP
//	\"userName\":\"Jane Doe\"         JSON embedded in a string
//
// A quoted value runs to its closing quote on the same line, spaces and
// backslash escapes included; an unterminated one is skipped. An unquoted
// value runs to the end of the line, and stops earlier at a tab, a quote,
// = or one of ) ] } < > | `; at a space, comma, semicolon or & followed by
// another `name=` / `name:`; and at a space followed by # (a comment). It is
// trimmed of trailing spaces, commas and semicolons. An unquoted value that starts like a nested
// structure or a YAML block, anchor, alias, tag or comment ({ [ | > & * ! #)
// is skipped.
//
// Fields come back in order. Values may overlap other fields' values: a field
// written inside a quoted value is found as well.
func Find(s string) []Field {
	var out []Field
	for _, m := range keyPattern.FindAllStringSubmatchIndex(s, -1) {
		open, cl := group(s, m, 1), group(s, m, 3)
		if open == ":" {
			if cl != "" {
				continue
			}
		} else if open != cl {
			continue
		}
		sep := s[m[8]:m[9]]
		p := m[1]
		if p < len(s) && (sep == "=" && s[p] == '=' || sep == ":" && s[p] == ':') {
			continue // == comparison, :: scope
		}
		start, end, ok := value(s, p)
		if !ok {
			continue
		}
		out = append(out, Field{Name: s[m[4]:m[5]], Start: start, End: end})
	}
	return out
}

func group(s string, m []int, g int) string {
	if m[2*g] < 0 {
		return ""
	}
	return s[m[2*g]:m[2*g+1]]
}

// value reads the value that starts at p.
func value(s string, p int) (start, end int, ok bool) {
	if p >= len(s) {
		return 0, 0, false
	}
	rest := s[p:]
	switch {
	case strings.HasPrefix(rest, `\"`), strings.HasPrefix(rest, `\'`):
		q := rest[:2]
		line := rest[2:]
		if i := strings.IndexAny(line, "\r\n"); i >= 0 {
			line = line[:i]
		}
		i := strings.Index(line, q)
		if i <= 0 {
			return 0, 0, false
		}
		return p + 2, p + 2 + i, true
	case rest[0] == '"' || rest[0] == '\'':
		q := rest[0]
		for i := 1; i < len(rest); i++ {
			switch rest[i] {
			case '\\':
				i++
			case '\r', '\n':
				return 0, 0, false
			case q:
				if i == 1 {
					return 0, 0, false
				}
				return p + 1, p + i, true
			}
		}
		return 0, 0, false
	}

	if strings.IndexByte("{[|>&*!#\r\n", rest[0]) >= 0 {
		return 0, 0, false
	}
	n := len(rest)
scan:
	for i := 0; i < len(rest); i++ {
		switch rest[i] {
		case '\r', '\n', '\t', '"', '\'', '`', '=', ')', ']', '}', '<', '>', '|':
			n = i
			break scan
		case ' ':
			if strings.HasPrefix(rest[i:], " #") || nextKey.MatchString(rest[i:]) {
				n = i
				break scan
			}
		case ',', ';', '&':
			if nextKey.MatchString(rest[i+1:]) {
				n = i
				break scan
			}
		}
	}
	v := strings.TrimRight(rest[:n], " ,;")
	if v == "" {
		return 0, 0, false
	}
	return p, p + len(v), true
}
