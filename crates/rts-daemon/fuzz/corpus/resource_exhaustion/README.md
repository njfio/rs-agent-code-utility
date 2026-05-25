# `resource_exhaustion` adversarial-input corpus

Seeds covering memory- and CPU-exhaustion shapes. Consumed by the
proptest properties (length-bound checks) and as reference inputs for
the regex / structural-query fuzz targets.

## What's covered

| File | Class | Why |
|---|---|---|
| `long_text_64k` | length cap | 64 KiB of `A` repeating. Past the daemon's 1024-char `text` cap and the proposed 64 KiB structural-query cap. Should be rejected upstream of the compile path. |
| `deep_json_nesting` | parser stress | 100-level nested `{"x":...}` — exercises the `serde_json::Value` parse path on the request envelope. |

## Note on seed sizes

Seeds are capped at 64 KiB to keep the git-tracked corpus small. The
actual fuzz targets receive inputs up to libFuzzer's default
`-max_len=4096` unless overridden; for the daemon's documented caps
the relevant test territory is well under 64 KiB. Larger inputs
(multi-MB) are covered by the property-test layer, not the fuzz layer.

## Promise validated

RESILIENCE.md §"Resource exhaustion".
