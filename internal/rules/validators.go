package rules

import "sort"

// Validators are checks that cannot be expressed as a regular expression.
// Rules refer to them by name in `validators:`.
var Validators = map[string]func(string) bool{
	// luhn: the digits of the value pass the Luhn checksum (card numbers).
	"luhn": luhn,
}

func validatorNames() []string {
	names := make([]string, 0, len(Validators))
	for n := range Validators {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func luhn(v string) bool {
	var digits []int
	for _, c := range v {
		if c >= '0' && c <= '9' {
			digits = append(digits, int(c-'0'))
		}
	}
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	sum := 0
	for i := range digits {
		d := digits[len(digits)-1-i]
		if i%2 == 1 {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
	}
	return sum%10 == 0
}
