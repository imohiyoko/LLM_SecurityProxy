// Package testsecret builds fake credentials for tests.
//
// The values are assembled at run time so that the repository itself never
// contains a literal that looks like a real secret to scanners.
package testsecret

import "strings"

// AWSAccessKey is AWS's documented example access key ID.
func AWSAccessKey() string { return "AKIA" + "IOSFODNN7" + "EXAMPLE" }

// AWSSecretKey is AWS's documented example secret access key.
func AWSSecretKey() string { return "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY" }

// GitHubToken is a syntactically valid, fake personal access token.
func GitHubToken() string { return "gh" + "p_" + strings.Repeat("a1B2", 9) }

// AnthropicKey is a syntactically valid, fake API key.
func AnthropicKey() string { return "sk-" + "ant-api03-" + strings.Repeat("Zz9_", 6) }

// JWT is a fake token with a well-formed shape.
func JWT() string {
	return "ey" + "JhbGciOiJIUzI1NiJ9" + ".ey" + "JzdWIiOiIxMjM0NTY3ODkwIn0" + ".c2lnbmF0dXJlLWZha2U"
}

// PrivateKey is a PEM block with fake content.
func PrivateKey() string {
	return "-----BEGIN " + "RSA PRIVATE KEY-----\nMIIEfakefakefakefake\nZmFrZWZha2U=\n-----END " + "RSA PRIVATE KEY-----"
}

// Card is a Luhn-valid test card number.
func Card() string { return "4111" + " 1111 1111 1111" }

// Card13 is a Luhn-valid 13-digit test card number (old Visa).
func Card13() string { return "4222" + "222222222" }

// Card14 is a Luhn-valid 14-digit test card number (Diners Club).
func Card14() string { return "3056" + "9309025904" }

// Passphrase is a letters-only secret value.
func Passphrase() string { return "MyPlain" + "SecretValue" }
