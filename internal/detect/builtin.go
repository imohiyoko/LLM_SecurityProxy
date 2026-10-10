package detect

import (
	"regexp"
	"strings"
)

// Builtin returns the default rule set. The rules favour precision: a false
// positive breaks the code the model is working on, so generic patterns carry
// validators that reject obvious code references.
func Builtin() []Rule {
	return []Rule{
		{
			Name: "private_key",
			Kind: "PRIVATE_KEY",
			Re:   regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----`),
		},
		{
			Name: "aws_access_key_id",
			Kind: "AWS_ACCESS_KEY",
			Re:   regexp.MustCompile(`\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b`),
		},
		{
			Name:  "aws_secret_access_key",
			Kind:  "AWS_SECRET_KEY",
			Re:    regexp.MustCompile(`(?i)aws.{0,30}?(?:secret|sk).{0,20}?[\s'"=:]([A-Za-z0-9/+]{40})(?:[^A-Za-z0-9/+]|$)`),
			Group: 1,
		},
		{
			Name: "github_token",
			Kind: "GITHUB_TOKEN",
			Re:   regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b`),
		},
		{
			Name: "slack_token",
			Kind: "SLACK_TOKEN",
			Re:   regexp.MustCompile(`\bxox[abposr]-[A-Za-z0-9-]{10,}\b`),
		},
		{
			Name: "slack_webhook",
			Kind: "SLACK_WEBHOOK",
			Re:   regexp.MustCompile(`https://hooks\.slack\.com/services/[A-Za-z0-9/_-]+`),
		},
		{
			Name: "anthropic_api_key",
			Kind: "ANTHROPIC_KEY",
			Re:   regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{20,}`),
		},
		{
			Name: "openai_api_key",
			Kind: "OPENAI_KEY",
			Re:   regexp.MustCompile(`\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,}`),
			Validate: func(v string) bool {
				return !strings.HasPrefix(v, "sk-ant-")
			},
		},
		{
			Name: "google_api_key",
			Kind: "GOOGLE_API_KEY",
			Re:   regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`),
		},
		{
			Name: "jwt",
			Kind: "JWT",
			Re:   regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`),
		},
		{
			Name:     "email",
			Kind:     "EMAIL",
			Re:       regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,24}\b`),
			Validate: validEmail,
		},
		{
			Name:     "credit_card",
			Kind:     "CREDIT_CARD",
			Re:       regexp.MustCompile(`\b(?:4\d{3}|5[1-5]\d{2}|2[2-7]\d{2}|3[47]\d{2}|35\d{2}|6011|65\d{2})(?:[ -]?\d){11,15}\b`),
			Validate: validCard,
		},
		{
			Name:     "generic_secret",
			Kind:     "SECRET",
			Re:       regexp.MustCompile(`(?i)(?:password|passwd|pwd|secret|client_secret|api[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?token)\b["']?\s*[:=]\s*["']?([^\s"'` + "`" + `,;]{8,})`),
			Group:    1,
			Validate: validGenericSecret,
		},
		{
			Name:     "ipv4",
			Kind:     "IPV4",
			Re:       regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b`),
			Validate: validIPv4,
			Optional: true,
		},
	}
}

var imageExt = regexp.MustCompile(`(?i)\.(png|jpe?g|gif|webp|svg|ico|avif)$`)

func validEmail(v string) bool {
	at := strings.LastIndexByte(v, '@')
	local, domain := strings.ToLower(v[:at]), strings.ToLower(v[at+1:])
	if imageExt.MatchString(domain) { // icon@2x.png
		return false
	}
	if local == "git" { // git@host:org/repo
		return false
	}
	for _, d := range []string{"example.com", "example.org", "example.net", "example.jp", "users.noreply.github.com"} {
		if domain == d || strings.HasSuffix(domain, "."+d) {
			return false
		}
	}
	return !strings.HasSuffix(domain, ".example") && !strings.HasSuffix(domain, ".invalid") && !strings.HasSuffix(domain, ".test")
}

func validCard(v string) bool {
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

var (
	dottedIdent = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)+$`)
	plainIdent  = regexp.MustCompile(`^[A-Za-z_]+$`)
	maskedLike  = regexp.MustCompile(`^(?:x+|\*+|\.+|<[^>]*>|\[[^\]]*\]|changeme|placeholder|redacted|your[_-].*)$`)
)

// validGenericSecret rejects values that look like code rather than secrets:
// `apiKey: process.env.API_KEY`, `password = getPassword()`, `token: tokenValue`.
func validGenericSecret(v string) bool {
	v = strings.TrimRight(v, ")]}")
	switch {
	case strings.ContainsAny(v, "(){}"),
		strings.HasPrefix(v, "$"), strings.HasPrefix(v, "%"), strings.HasPrefix(v, "@"),
		strings.Contains(v, placeholderPrefix),
		dottedIdent.MatchString(v),
		maskedLike.MatchString(strings.ToLower(v)):
		return false
	case plainIdent.MatchString(v) && len(v) < 24:
		return false
	}
	return true
}

const placeholderPrefix = "__LLMSP_"

func validIPv4(v string) bool {
	return v != "127.0.0.1" && v != "0.0.0.0" && v != "255.255.255.255" && !strings.HasPrefix(v, "0.")
}
