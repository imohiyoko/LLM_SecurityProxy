# [security] Credit-card regex requires >=15 digits but the luhn validator accepts 13; 13/14-digit cards are missed

## Summary
The credit-card pattern structurally matches 15–19 digits (4-digit prefix + `(?:[ -]?\d){11,15}`), while the `luhn` validator accepts 13–19 digits. luhn-valid 13- and 14-digit numbers (old Visa, Diners) never reach the validator and are not masked.

## Affected code
- pattern (15–19 digits): [pii.yaml#L17](https://github.com/imohiyoko/LLM_SecurityProxy/blob/aa8269efc12e12e841817b112929c9cbb90b6f1d/internal/rules/builtin/pii.yaml#L17)
- luhn accepts 13–19: [validators.go#L21-L28](https://github.com/imohiyoko/LLM_SecurityProxy/blob/aa8269efc12e12e841817b112929c9cbb90b6f1d/internal/rules/validators.go#L21-L28)

## Reproduction
```
luhn("4222222222222") == true        (13-digit)
"card 4222222222222 end"    -> 0 matches (NOT masked)
"card 4111111111111111 end" -> masked (CREDIT_CARD)
```

## Suggested fix
Widen the repetition to `{9,15}` (13–19 digits total) and let `luhn` gate the digit length, instead of enforcing a stricter lower bound in the regex.
