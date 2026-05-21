# `unicode_confusables` adversarial-input corpus

Seeds covering Unicode confusable characters and NFC/NFD normalisation
mismatches. Consumed by the proptest properties
`find_symbol_unicode_never_panics` and `grep_literal_unicode_never_panics`
in `crates/rts-daemon/tests/adversarial_proptest.rs`.

## What's covered

| File | Class | Why |
|---|---|---|
| `zwj_admin` | zero-width joiner | `a` + U+200D (ZWJ) + `dmin` — visually identical to `admin` but a distinct byte sequence. |
| `rtl_override` | RTL override | U+202E + `admin` + U+202C — direction-override pair the daemon must accept without parsing it as anything special. |
| `nfc_resume` | NFC normal form | `résumé` written as `r e CC81 s u m e CC81` — NFC form (precomposed). |
| `nfd_resume` | NFD normal form | Same visual text, decomposed form. The daemon does NOT NFC-normalise input strings (only canonical paths on macOS); both should round-trip distinctly. |

## Promise validated

RESILIENCE.md §"Unicode handling".
