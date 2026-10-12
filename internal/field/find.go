package field

import (
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Field is a value assigned to a named field.
type Field struct {
	// Name is the field name as written, without quotes.
	Name string
	// Key is Name prepared for KeySet.Has.
	Key Key
	// Start and End are the byte offsets of the value, without its quotes.
	Start, End int
}

// keyPattern matches a field name and its separator, but not the value, so
// that a field written inside another field's value is found too.
//
// The name is a word of letters, digits, _ . - (any script), optionally
// quoted ("name", 'name', \"name\"), a Ruby symbol (:name), a command-line
// flag (--name) or a subscript (['name'], ["name"]). The separator is :, =,
// :=, => or a full-width colon. An unbracketed name may not follow a letter,
// digit or one of _ . -, so that it is never the tail of a longer name.
//
// Groups: 1 opening [ and quote (tried first, so that ['name'] is read as a
// subscript); 2 opening quote / : / -- ; 3 name; 4 closing quote and ] ;
// 5 separator.
var keyPattern = regexp.MustCompile(`(?:(\[\\?["'])|(?:^|[^\pL\pN_.-])(\\?["']|:|--?)?)([\pL_][\pL\pN_.-]*)(\\?["']\]?)?[ \t]*(:=|=>|=|:|：)`)

// labelPattern matches a label of two to four words at the start of a line,
// as in forms and e-mails ("Full Name: Jane Doe").
var labelPattern = regexp.MustCompile(`(?m)^[ \t]*((?:\pL[\pL\pN]*[ \t]){1,3}\pL[\pL\pN]*)[ \t]*(:|：)`)

// xmlPattern matches a one-line XML element with text content. The opening
// and closing names are compared in code (RE2 has no backreferences).
var xmlPattern = regexp.MustCompile(`<([\pL_][\pL\pN_.:-]*)(?:\s[^<>]*)?>([^<\r\n]*)</([\pL_][\pL\pN_.:-]*)>`)

// nextKey is what may follow a soft stop in an unquoted value for the value to
// end there: another field name and separator.
var nextKey = regexp.MustCompile(`^[ \t]*(?:--?)?[\pL_][\pL\pN_.-]*[ \t]*(?::=|=>|=|:[ \t]|：)`)

// codeValue matches an unquoted value that is code rather than data: a call
// or subscript, a template or variable, or an expression. Such values are
// skipped by every field rule; quoted values are always data.
var codeValue = regexp.MustCompile(`[\pL\pN_$.]\(|[\pL\pN_$.]\[|^[$#%]\{|^\{\{|^%\(|^\$[\pL_][\pL\pN_]*$|\s(?:\+|\*|\|\||\?\?|&&)(?:\s|$)`)

// typeNames are unquoted values that are type annotations (userName: string).
var typeNames = map[string]bool{
	"str": true, "string": true, "String": true, "int": true, "integer": true, "number": true,
	"float": true, "bool": true, "boolean": true, "any": true, "object": true, "text": true,
	"char": true, "varchar": true, "bytes": true,
}

// Find returns every field assignment in s whose value can be read:
//
//	"userName": "Jane Doe"            JSON (\" escapes allowed)
//	user_name: "Jane Doe"             YAML, logs
//	user_name: Jane Doe               unquoted, see below
//	user_name="Jane Doe"              logfmt, env, Python, HTML attributes
//	USER_NAME='Jane Doe'              shell
//	:user_name => "Jane Doe"          Ruby
//	'user_name' => 'Jane Doe'         PHP
//	$row['user_name'] = 'Jane Doe'    subscripts
//	--user-name=Jane                  command-line flags
//	\"userName\":\"Jane Doe\"         JSON embedded in a string
//	Full Name: Jane Doe               a label at the start of a line
//	<user_name>Jane Doe</user_name>   XML
//	氏名：山田太郎                      any script, full-width colon
//
// A quoted value runs to its closing quote on the same line, spaces and
// backslash escapes included, and a doubled quote ('O”Brien') is part of it;
// an unterminated one is skipped. A string prefix (u'..', f"..", b'..') is
// skipped. An unquoted value runs to the end of the line, and stops earlier
// at a tab, a quote (but not an apostrophe inside a word: O'Brien), = or one
// of < > | ` and an unbalanced ) ] }; at a space, comma, semicolon or &
// followed by another `name=` / `name:`; and at a space followed by # (a
// comment). It is trimmed of trailing spaces, commas and semicolons.
//
// No value is read when the separator is followed directly by another field
// (user_name= display_name=...), or by a nested structure or a YAML block,
// anchor, alias, tag or comment ({ [ | > & * ! #). Unquoted values that are
// code (calls, subscripts, templates, variables, expressions, type
// annotations) are skipped.
//
// Fields come back in order of their values. Values may overlap: a field
// written inside a quoted value is found as well.
func Find(s string) []Field {
	var out []Field
	add := func(name string, start, end int) {
		out = append(out, Field{Name: name, Key: NewKey(name), Start: start, End: end})
	}
	for _, m := range keyPattern.FindAllStringSubmatchIndex(s, -1) {
		if !quotesMatch(group(s, m, 2), group(s, m, 1), group(s, m, 4)) {
			continue
		}
		if start, end, ok := value(s, m[1], group(s, m, 5)); ok {
			add(group(s, m, 3), start, end)
		}
	}
	for _, m := range labelPattern.FindAllStringSubmatchIndex(s, -1) {
		if start, end, ok := value(s, m[1], group(s, m, 2)); ok {
			add(group(s, m, 1), start, end)
		}
	}
	for _, m := range xmlPattern.FindAllStringSubmatchIndex(s, -1) {
		name := group(s, m, 1)
		if name != group(s, m, 3) {
			continue
		}
		start, end := m[4], m[5]
		for start < end && s[start] == ' ' {
			start++
		}
		for end > start && s[end-1] == ' ' {
			end--
		}
		if start < end {
			if i := strings.LastIndexByte(name, ':'); i >= 0 {
				name = name[i+1:] // namespace prefix
			}
			add(name, start, end)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Start < out[j].Start })
	return out
}

// quotesMatch checks the quoting around a name. A name opened by a quote
// that does not close it is read as unquoted: the quote belongs to an
// enclosing string (-e "FULL_NAME=Jane").
func quotesMatch(open, bracket, cl string) bool {
	if bracket != "" {
		return cl == bracket[1:]+"]"
	}
	switch {
	case strings.HasSuffix(cl, "]"):
		return false
	case cl == "":
		return true
	case open == ":" || strings.HasPrefix(open, "-"):
		return false
	}
	return open == cl
}

func group(s string, m []int, g int) string {
	if m[2*g] < 0 {
		return ""
	}
	return s[m[2*g]:m[2*g+1]]
}

// value reads the value after the separator sep, which ends at p.
func value(s string, p int, sep string) (start, end int, ok bool) {
	if p < len(s) && (sep == "=" && s[p] == '=' || sep == ":" && s[p] == ':') {
		return 0, 0, false // == comparison, :: scope
	}
	for p < len(s) && (s[p] == ' ' || s[p] == '\t') {
		p++
	}
	if p >= len(s) {
		return 0, 0, false
	}
	rest := s[p:]
	// String prefix: u'..', f"..", rb'..'.
	if i := strings.IndexAny(rest[:min(3, len(rest))], `"'`); i > 0 && strings.Trim(rest[:i], "uUbBrRfF") == "" {
		p, rest = p+i, rest[i:]
	}

	switch {
	case strings.HasPrefix(rest, `\"`), strings.HasPrefix(rest, `\'`):
		// Find the closing quote first and look for a line break only before
		// it, so a long line with many fields is not rescanned per field.
		q := rest[:2]
		i := strings.Index(rest[2:], q)
		if i <= 0 || strings.ContainsAny(rest[2:2+i], "\r\n") {
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
				if i+1 < len(rest) && rest[i+1] == q {
					i++ // doubled quote: 'O''Brien'
					continue
				}
				return p + 1, p + i, true
			}
		}
		return 0, 0, false
	}

	if strings.IndexByte("{[|>&*!#\r\n", rest[0]) >= 0 || nextKey.MatchString(rest) {
		return 0, 0, false
	}
	n := len(rest)
	depth := 0
	typed := false // `name: Type = default`
scan:
	for i := 0; i < len(rest); i++ {
		switch rest[i] {
		case '\r', '\n', '\t', '"', '`', '<', '>', '|':
			n = i
			break scan
		case '=':
			n, typed = i, sep == ":"
			break scan
		case '\'':
			// An apostrophe inside a word (O'Brien, O''Brien) is part of it.
			j := i + 1
			if j < len(rest) && rest[j] == '\'' {
				j++
			}
			if !inWord(rest, i) || !isLetter(rest[j:]) {
				n = i
				break scan
			}
			i = j - 1
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth == 0 {
				n = i
				break scan
			}
			depth--
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
	if v == "" || typed || typeNames[v] || codeValue.MatchString(v) {
		return 0, 0, false
	}
	return p, p + len(v), true
}

// inWord reports whether the character before byte i is a letter.
func inWord(s string, i int) bool {
	r, _ := utf8.DecodeLastRuneInString(s[:i])
	return unicode.IsLetter(r)
}

func isLetter(s string) bool {
	r, _ := utf8.DecodeRuneInString(s)
	return unicode.IsLetter(r)
}
