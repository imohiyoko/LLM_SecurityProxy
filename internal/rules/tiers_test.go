package rules

import (
	"strings"
	"testing"

	"github.com/imohiyoko/LLM_SecurityProxy/internal/detect"
)

const tieredRules = `
id: org/hr
rules:
  - id: salary
    kind: SALARY
    keys: [salary, annual_income, 年収]
    tiers:
      - {label: under_3m, below: 3000000}
      - {label: 3m_6m, below: 600万}
      - {label: 6m_10m, below: "¥10,000,000"}
      - {label: 10m_plus, at_least: 1000万}
  - id: disability
    kind: DISABILITY
    keys: [disability_grade, 障害等級]
    tiers:
      - {label: severe, values: [1級, 2級]}
      - {label: moderate, match: '^[3-4]級$'}
      - {label: other}
  - id: bonus
    kind: BONUS
    pattern: 'bonus of (\S+)'
    group: 1
    tiers:
      - {label: small, below: 1M}
      - {label: large}
`

func kinds(d *detect.Detector, text string) map[string]string {
	out := map[string]string{}
	for _, m := range d.Find(text) {
		out[text[m.Start:m.End]] = m.Kind
	}
	return out
}

func TestTiers(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "hr.yaml", tieredRules)
	d := detector(t, []string{dir}, Selection{})

	got := kinds(d, `{"salary": "2,800,000", "annualIncome": "720万円"}
年収: 1200万円
salary=非公開
disability_grade: 2級
障害等級=4級
disabilityGrade: 6級
paid a bonus of $1.5M today
`)
	want := map[string]string{
		"2,800,000": "SALARY_UNDER_3M",
		"720万円":     "SALARY_6M_10M",
		"1200万円":    "SALARY_10M_PLUS",
		"非公開":       "SALARY", // not an amount: masked without a tier
		"2級":        "DISABILITY_SEVERE",
		"4級":        "DISABILITY_MODERATE",
		"6級":        "DISABILITY_OTHER",
		"$1.5M":     "BONUS_LARGE",
	}
	for v, k := range want {
		if got[v] != k {
			t.Errorf("%q: kind %q, want %q (all: %v)", v, got[v], k, got)
		}
	}

	// A value whose field name is known from structure.
	if ms := d.Field("salary", "5000000"); len(ms) != 1 || ms[0].Kind != "SALARY_3M_6M" {
		t.Errorf("Field(salary) = %+v", ms)
	}
}

func TestTierErrors(t *testing.T) {
	cases := map[string]string{
		"label":      "tiers: [{label: 'low-pay', below: 1}]",
		"long":       "tiers: [{label: abcdefghijklmnopqrstuvwxyz0123, below: 1}]",
		"duplicate":  "tiers: [{label: a, below: 1}, {label: A, below: 2}]",
		"two":        "tiers: [{label: a, below: 1, match: x}]",
		"amount":     "tiers: [{label: a, below: lots}]",
		"range":      "tiers: [{label: a, at_least: 2, below: 1}]",
		"catch-all":  "tiers: [{label: a}, {label: b, below: 1}]",
		"bad regexp": "tiers: [{label: a, match: '('}]",
	}
	for name, tiers := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, dir, "x.yaml", "id: x\nrules:\n  - id: r\n    kind: SALARY\n    keys: [salary]\n    "+tiers+"\n")
			c, err := Load([]string{dir})
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.Compile(Selection{})
			if err == nil || !strings.Contains(err.Error(), "tiers[") {
				t.Errorf("err = %v, want a tiers error", err)
			}
		})
	}
}

func TestModeErrors(t *testing.T) {
	cases := map[string]string{
		"unknown":        "mode: hide",
		"keep restore":   "keep_last: 4",
		"keep negative":  "{mode: redact, keep_last: -1}",
		"keep too many":  "{mode: redact, keep_first: 6, keep_last: 6}",
		"digits restore": "digits: 3",
		"digits range":   "{mode: approximate, digits: 9}",
		"tiers approx":   "{mode: approximate, tiers: [{label: a}]}",
	}
	for name, extra := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			body := "id: x\nrules:\n  - id: r\n    kind: SALARY\n    keys: [salary]\n"
			if strings.HasPrefix(extra, "{") {
				body = "id: x\nrules:\n  - " + strings.TrimSuffix(extra, "}") + ", id: r, kind: SALARY, keys: [salary]}\n"
			} else {
				body += "    " + extra + "\n"
			}
			writeFile(t, dir, "x.yaml", body)
			c, err := Load([]string{dir})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.Compile(Selection{}); err == nil {
				t.Errorf("no error for %s", body)
			} else {
				t.Log(err)
			}
		})
	}
	// Too long a kind for approximate.
	dir := t.TempDir()
	writeFile(t, dir, "x.yaml", "id: x\nrules:\n  - {id: r, kind: VERY_LONG_KIND_NAME_HERE, keys: [a], mode: approximate}\n")
	c, err := Load([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Compile(Selection{}); err == nil || !strings.Contains(err.Error(), "too long") {
		t.Errorf("err = %v", err)
	}
}

func TestLinkErrors(t *testing.T) {
	for name, extra := range map[string]string{
		"restore": "{link: context}",
		"unknown": "{mode: redact, link: row}",
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, dir, "x.yaml", "id: x\nrules:\n  - "+strings.TrimSuffix(extra, "}")+", id: r, kind: K, keys: [k]}\n")
			c, err := Load([]string{dir})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.Compile(Selection{}); err == nil || !strings.Contains(err.Error(), "link") {
				t.Errorf("err = %v", err)
			}
		})
	}
}
