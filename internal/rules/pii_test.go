package rules

import (
	"strings"
	"testing"

	"github.com/imohiyoko/LLM_SecurityProxy/internal/testsecret"
)

// A card followed by an expiry date or CVV must still be masked, and only the
// card number itself.
func TestCreditCardTrailingDigits(t *testing.T) {
	d := detector(t, nil, Selection{})
	const rule = "builtin/pii:credit_card"
	spaced := testsecret.Card()
	dashed := strings.ReplaceAll(spaced, " ", "-")
	plain := strings.ReplaceAll(spaced, " ", "")
	amex := "3782" + " 822463 10005"
	diners := "3056" + " 930902 5904"
	cases := []struct{ text, want string }{
		{spaced, spaced},
		{spaced + ", exp 12/29", spaced},
		{spaced + " 12/29", spaced},
		{spaced + " 123", spaced},
		{spaced + " 12 29 123", spaced},
		{spaced + " 1229", spaced},
		{dashed + " 12/29", dashed},
		{dashed + " 123", dashed},
		{plain + " 12/29", plain},
		{plain + " 123", plain},
		{amex + " 12/29 1234", amex},
		{strings.ReplaceAll(amex, " ", "-") + " 1234", strings.ReplaceAll(amex, " ", "-")},
		{diners + " 123", diners},
		{"card: " + spaced + " exp 12/29 cvv 123", spaced},
	}
	for _, c := range cases {
		got := found(d, c.text)
		if got[rule] != c.want {
			t.Errorf("%q: got %q, want %q (all: %v)", c.text, got[rule], c.want, got)
		}
	}
}

func TestCreditCardNegative(t *testing.T) {
	d := detector(t, nil, Selection{})
	for _, text := range []string{
		"4111 1111-1111 1111",          // mixed separators
		"4111 1111 1111 1112 12/29",    // fails luhn
		"order 4111111111111111111111", // too long to be a card
		"phone 4111 1111",
	} {
		if got := found(d, text); got["builtin/pii:credit_card"] != "" {
			t.Errorf("%q: unexpected match %v", text, got)
		}
	}
}
