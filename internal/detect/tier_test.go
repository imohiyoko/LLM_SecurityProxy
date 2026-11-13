package detect

import (
	"regexp"
	"testing"
)

func TestParseNumber(t *testing.T) {
	cases := []struct {
		in   string
		want float64
	}{
		{"5200000", 5200000},
		{"5,200,000", 5200000},
		{"5_200_000", 5200000},
		{"¥5,200,000", 5200000},
		{"￥５，２００，０００", 5200000},
		{"5,200,000円", 5200000},
		{"520万", 5200000},
		{"520万円", 5200000},
		{"520.5万円", 5205000},
		{"1千万", 10000000},
		{"1億2000万円", 120000000},
		{"3百万円", 3000000},
		{"30万円/月", 300000},
		{"$120k", 120000},
		{"120K USD", 120000},
		{"USD 120,000", 120000},
		{"5.2M", 5200000},
		{"1.5bn", 1500000000},
		{"-3,000", -3000},
		{"€ 85000 /year", 85000},
		{" 42 ", 42},
	}
	for _, c := range cases {
		got, ok := ParseNumber(c.in)
		if !ok || got != c.want {
			t.Errorf("ParseNumber(%q) = %v, %v; want %v", c.in, got, ok, c.want)
		}
	}
	for _, in := range []string{"", "abc", "5 months", "500万〜600万", "about 5M", "5M per year", "1.2.3", "万", "円", "N/A", "5,", "100 apples"} {
		if got, ok := ParseNumber(in); ok {
			t.Errorf("ParseNumber(%q) = %v, true; want not a number", in, got)
		}
	}
}

func TestKindFor(t *testing.T) {
	salary := Rule{Kind: "SALARY", Tiers: []Tier{
		{Label: "UNDER_3M", Below: 3e6, HasBelow: true},
		{Label: "3M_6M", Below: 6e6, HasBelow: true},
		{Label: "6M_PLUS", AtLeast: 6e6, HasAtLeast: true},
	}}
	for v, want := range map[string]string{
		"2,999,999": "SALARY_UNDER_3M",
		"300万円":     "SALARY_3M_6M",
		"5.99M":     "SALARY_3M_6M",
		"6000000":   "SALARY_6M_PLUS",
		"1億円":       "SALARY_6M_PLUS",
		"非公開":       "SALARY", // not a number: masked, without a tier
		"500万〜600万": "SALARY",
	} {
		if got := salary.kindFor(v); got != want {
			t.Errorf("salary kindFor(%q) = %q, want %q", v, got, want)
		}
	}

	band := Rule{Kind: "PAY", Tiers: []Tier{{Label: "MID", AtLeast: 100, HasAtLeast: true, Below: 200, HasBelow: true}}}
	for v, want := range map[string]string{"99": "PAY", "100": "PAY_MID", "199.9": "PAY_MID", "200": "PAY"} {
		if got := band.kindFor(v); got != want {
			t.Errorf("band kindFor(%q) = %q, want %q", v, got, want)
		}
	}

	disability := Rule{Kind: "DISABILITY", Tiers: []Tier{
		{Label: "SEVERE", Values: []string{"1級", "2級"}},
		{Label: "MODERATE", Match: regexp.MustCompile(`^[3-4]級$`)},
		{Label: "NONE", Values: []string{"なし", "none"}},
		{Label: "OTHER"},
	}}
	for v, want := range map[string]string{
		"1級":   "DISABILITY_SEVERE",
		" 2級 ": "DISABILITY_SEVERE",
		"4級":   "DISABILITY_MODERATE",
		"None": "DISABILITY_NONE",
		"6級":   "DISABILITY_OTHER",
	} {
		if got := disability.kindFor(v); got != want {
			t.Errorf("disability kindFor(%q) = %q, want %q", v, got, want)
		}
	}

	if got := (&Rule{Kind: "NAME"}).kindFor("Jane"); got != "NAME" {
		t.Errorf("untiered kindFor = %q", got)
	}
}
