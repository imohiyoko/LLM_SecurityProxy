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
		// Mixed separators.
		{"4111 1111-1111 1111", "4111 1111-1111 1111"},
		{"4111-1111 1111-1111 12/29", "4111-1111 1111-1111"},
		{"3782-822463 10005", "3782-822463 10005"},
	}
	for _, c := range cases {
		got := found(d, c.text)
		if got[rule] != c.want {
			t.Errorf("%q: got %q, want %q (all: %v)", c.text, got[rule], c.want, got)
		}
	}
}

// 19-digit cards written 4-4-4-4-3 are matched by their own rule, so that the
// 4-4-4-x layout above can still leave a trailing CVV out of the card.
func TestCreditCard19(t *testing.T) {
	d := detector(t, nil, Selection{})
	const rule = "builtin/pii:credit_card_19"
	card := "6011" + " 0000 0000 0000 001"
	cases := []struct{ text, want string }{
		{card, card},
		{card + " 12/29", card},
		{strings.ReplaceAll(card, " ", "-"), strings.ReplaceAll(card, " ", "-")},
		{"6011 0000-0000 0000 001", "6011 0000-0000 0000 001"},
	}
	for _, c := range cases {
		got := found(d, c.text)
		if got[rule] != c.want {
			t.Errorf("%q: got %q, want %q (all: %v)", c.text, got[rule], c.want, got)
		}
	}
	// A 16-digit card and its CVV look the same; the CVV fails luhn here.
	if got := found(d, testsecret.Card()+" 123"); got[rule] != "" {
		t.Errorf("card + CVV matched as a 19-digit card: %v", got)
	}
}

func TestCreditCardNegative(t *testing.T) {
	d := detector(t, nil, Selection{})
	for _, text := range []string{
		"4111 1111 1111 1112 12/29",    // fails luhn
		"order 4111111111111111111111", // too long to be a card
		"phone 4111 1111",
	} {
		if got := found(d, text); got["builtin/pii:credit_card"] != "" {
			t.Errorf("%q: unexpected match %v", text, got)
		}
	}
}
