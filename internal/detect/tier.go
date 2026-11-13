package detect

import (
	"math"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/imohiyoko/LLM_SecurityProxy/internal/placeholder"
)

// Tier is one level of a tiered rule. A tiered rule still masks the whole
// value, but writes the label of the first tier that the value falls into
// after its kind (SALARY_3M_6M), so the model can tell the range or class of
// a value without seeing it.
//
// A tier sets one kind of condition: an amount range (Below, AtLeast or
// both), Values or Match. Without one it takes every value that reached it,
// numbers or not, and must be the last tier.
type Tier struct {
	// Label is appended to the rule's kind: [A-Z0-9_].
	Label string
	// Below, when HasBelow is set, takes values whose number (see
	// ParseNumber) is less than it. A value that is not a number does not
	// match any Below tier.
	Below    float64
	HasBelow bool
	// AtLeast, when HasAtLeast is set, takes values whose number is at least
	// it. With Below as well, the tier is the range between them.
	AtLeast    float64
	HasAtLeast bool
	// Values takes values equal to one of them, ignoring case and
	// surrounding spaces.
	Values []string
	// Match takes values matching the pattern.
	Match *regexp.Regexp
}

// matches reports whether v falls into the tier. n is v as a number; ok is
// false when v is not one.
func (t *Tier) matches(v string, n float64, ok bool) bool {
	switch {
	case t.HasBelow || t.HasAtLeast:
		return ok && (!t.HasBelow || n < t.Below) && (!t.HasAtLeast || n >= t.AtLeast)
	case len(t.Values) > 0:
		tv := strings.TrimSpace(v)
		for _, c := range t.Values {
			if strings.EqualFold(tv, strings.TrimSpace(c)) {
				return true
			}
		}
		return false
	case t.Match != nil:
		return t.Match.MatchString(v)
	}
	return true
}

// kindFor returns the kind written for value v: the rule's kind, followed by
// the label of the first tier v falls into. A value no tier takes keeps the
// plain kind; it is still masked.
func (r *Rule) kindFor(v string) string {
	if r.Mode == ModeApproximate {
		if n, ok := ParseNumber(v); ok {
			// An amount too large to fit the kind segment keeps the plain kind
			// rather than a truncated, wrong figure.
			if k := placeholder.NormalizeKind(r.Kind) + "_ABOUT_" + Approximate(n, r.ApproxDigits); len(k) <= placeholder.MaxKindLen {
				return k
			}
		}
		return r.Kind
	}
	if len(r.Tiers) == 0 {
		return r.Kind
	}
	n, ok := ParseNumber(v)
	for i := range r.Tiers {
		if r.Tiers[i].matches(v, n, ok) {
			// The same base as the label was checked against at load time,
			// so kind and label always fit the placeholder together.
			return placeholder.NormalizeKind(r.Kind) + "_" + r.Tiers[i].Label
		}
	}
	return r.Kind
}

// Multipliers for unit suffixes after a number. Japanese units chain
// (1億2千500万); a Latin suffix ends the number.
var (
	jaSmallUnits = map[string]float64{"千": 1e3, "百": 1e2}
	jaLargeUnits = map[string]float64{"万": 1e4, "億": 1e8, "兆": 1e12}
	enUnits      = map[string]float64{
		"k": 1e3, "K": 1e3,
		"m": 1e6, "M": 1e6, "mm": 1e6, "MM": 1e6, "mn": 1e6,
		"b": 1e9, "B": 1e9, "bn": 1e9,
	}
)

// Currency signs and codes that may surround a number. They are only
// stripped from the ends, so "100 apples" is not a number.
var currencyAffixes = []string{
	"¥", "￥", "$", "＄", "€", "£", "円", "ドル", "元",
	"JPY", "USD", "EUR", "GBP", "CNY", "jpy", "usd", "eur", "gbp", "cny",
}

// ParseNumber reads an amount written the way people write salaries and other
// figures: digits with , or _ separators, a decimal point, full-width digits,
// a currency sign or code before or after, a Latin suffix (k, M, B) and
// Japanese units (千, 万, 億, 兆, chained as in 1億2000万 or 1千万). ok is false for
// anything else, including ranges and text around the figure.
func ParseNumber(v string) (float64, bool) {
	s := strings.Map(func(r rune) rune {
		switch {
		case r >= '０' && r <= '９':
			return r - '０' + '0'
		case r == '，':
			return ','
		case r == '．':
			return '.'
		case r == '－' || r == '−':
			return '-'
		}
		return r
	}, strings.TrimSpace(v))

	neg := false
	if strings.HasPrefix(s, "-") {
		neg, s = true, strings.TrimSpace(s[1:])
	}
	s = trimCurrency(s)
	if strings.HasPrefix(s, "-") && !neg {
		neg, s = true, strings.TrimSpace(s[1:])
	}
	if s == "" {
		return 0, false
	}

	// Japanese numerals group like 1億2千500万: digits, optionally scaled by
	// a small unit (千, 百), add up to a group until a large unit (万, 億, 兆)
	// multiplies the whole group. After a bare figure only a large unit or
	// the end may follow.
	total, group := 0.0, 0.0
	pending, seen := false, false
	for {
		s = strings.TrimLeftFunc(s, unicode.IsSpace)
		if s == "" {
			break
		}
		if u, size := leadingUnit(s, jaLargeUnits); size > 0 {
			if !pending {
				return 0, false
			}
			total += group * u
			group, pending, s = 0, false, s[size:]
			continue
		}
		num, rest := leadingNumber(s)
		if num == "" {
			return 0, false
		}
		f, err := strconv.ParseFloat(num, 64)
		if err != nil {
			return 0, false
		}
		seen = true
		rest = strings.TrimLeftFunc(rest, unicode.IsSpace)
		if u, size := leadingUnit(rest, jaSmallUnits); size > 0 {
			group, pending, s = group+f*u, true, rest[size:]
			continue
		}
		if u, size := leadingUnit(rest, jaLargeUnits); size > 0 {
			total += (group + f) * u
			group, pending, s = 0, false, rest[size:]
			continue
		}
		if u, size := leadingEnUnit(rest); size > 0 {
			// A Latin suffix ends the figure: 5.2M, $120k.
			if total != 0 || group != 0 || strings.TrimSpace(rest[size:]) != "" {
				return 0, false
			}
			total, s = f*u, ""
			break
		}
		group, pending = group+f, true
		if rest != "" {
			if _, size := leadingUnit(rest, jaLargeUnits); size == 0 {
				return 0, false
			}
		}
		s = rest
	}
	total += group
	if !seen || math.IsInf(total, 0) || math.IsNaN(total) {
		return 0, false
	}
	if neg {
		total = -total
	}
	return total, true
}

// Period markers after an amount (月給30万円/月). They are stripped from the
// end only; the rule's keys say whether the amount is monthly or yearly.
var periodSuffixes = []string{"/年", "/月", "/yr", "/year", "/mo", "/month", "/h", "/hr", "/hour", "/時", "/時間"}

func trimCurrency(s string) string {
	for changed := true; changed; {
		changed = false
		for _, p := range periodSuffixes {
			if t, ok := strings.CutSuffix(s, p); ok {
				s, changed = strings.TrimSpace(t), true
			}
		}
		for _, a := range currencyAffixes {
			if t, ok := strings.CutPrefix(s, a); ok {
				s, changed = strings.TrimSpace(t), true
			}
			if t, ok := strings.CutSuffix(s, a); ok {
				s, changed = strings.TrimSpace(t), true
			}
		}
	}
	return s
}

// leadingNumber splits off a number at the start of s: digits with , or _
// group separators and at most one decimal point. Separators are dropped.
func leadingNumber(s string) (num, rest string) {
	var b strings.Builder
	i, dot, digits := 0, false, 0
	for i < len(s) {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			b.WriteByte(c)
			digits++
		case (c == ',' || c == '_') && digits > 0 && i+1 < len(s) && s[i+1] >= '0' && s[i+1] <= '9':
		case c == '.' && !dot && digits > 0 && i+1 < len(s) && s[i+1] >= '0' && s[i+1] <= '9':
			b.WriteByte(c)
			dot = true
		default:
			return b.String(), s[i:]
		}
		i++
	}
	return b.String(), s[i:]
}

func leadingUnit(s string, units map[string]float64) (float64, int) {
	for k, u := range units {
		if strings.HasPrefix(s, k) {
			return u, len(k)
		}
	}
	return 0, 0
}

func leadingEnUnit(s string) (float64, int) {
	best, size := 0.0, 0
	for k, u := range enUnits {
		if strings.HasPrefix(s, k) && len(k) > size {
			best, size = u, len(k)
		}
	}
	// A unit must not run into more letters: "5 months" is not 5M.
	if size > 0 && size < len(s) {
		c := s[size]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' {
			return 0, 0
		}
	}
	return best, size
}

// Approximate rounds n to digits significant digits (at least 1) and writes it
// with the largest of K, M, B and T that leaves a whole number, in the
// [A-Z0-9] alphabet of a kind: 4,523,000 with 2 digits is 4500K, 125,000,000
// is 130M, 980 is 980. A negative amount starts with MINUS.
func Approximate(n float64, digits int) string {
	if digits < 1 {
		digits = 1
	}
	prefix := ""
	if n < 0 {
		prefix, n = "MINUS", -n
	}
	if n == 0 {
		return prefix + "0"
	}
	exp := math.Floor(math.Log10(n))
	step := math.Pow(10, exp-float64(digits-1))
	r := math.Round(n/step) * step
	if r < 1 {
		return prefix + "0"
	}
	for _, u := range []struct {
		suffix string
		size   float64
	}{{"T", 1e12}, {"B", 1e9}, {"M", 1e6}, {"K", 1e3}} {
		if r >= u.size && math.Mod(r, u.size) == 0 {
			return prefix + strconv.FormatFloat(r/u.size, 'f', 0, 64) + u.suffix
		}
	}
	return prefix + strconv.FormatFloat(r, 'f', 0, 64)
}
