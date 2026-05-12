//! Token counting for bench output.
//!
//! v0 uses the protocol-v0 §11.1 approximator: `bytes / 3` (round up). The
//! oracle — Anthropic SDK `messages.countTokens()` — is gated behind the
//! `--with-network` flag and an env-only `RTS_BENCH_ANTHROPIC_API_KEY`; that
//! lands later, alongside the actual S2 reduction-percentage report. For
//! now, every measurement uses the same `bytes / 3` counter on both sides
//! of the comparison so the *ratio* is meaningful even if the absolute
//! numbers don't match what an LLM would tokenise.

/// Approximate token count: `bytes / 3` rounded up. Matches the daemon's
/// `tokens_returned` formula so bench numbers line up with what the agent
/// would actually see in a `read_symbol` response.
pub fn approx_tokens(bytes: usize) -> u64 {
    (bytes as u64).div_ceil(3)
}

/// Sum of `approx_tokens` over an iterator of byte buffers.
pub fn approx_tokens_total<'a, I>(iter: I) -> u64
where
    I: IntoIterator<Item = &'a [u8]>,
{
    iter.into_iter().map(|b| approx_tokens(b.len())).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_byte_is_one_token() {
        // div_ceil(1, 3) = 1. The protocol pins this so a tiny payload is
        // never "0 tokens" — that would let the agent over-trust the
        // budget calculation.
        assert_eq!(approx_tokens(1), 1);
    }

    #[test]
    fn three_bytes_is_one_token() {
        assert_eq!(approx_tokens(3), 1);
    }

    #[test]
    fn four_bytes_is_two_tokens() {
        assert_eq!(approx_tokens(4), 2);
    }

    #[test]
    fn empty_is_zero() {
        assert_eq!(approx_tokens(0), 0);
    }

    #[test]
    fn total_sums_correctly() {
        let buffers: &[&[u8]] = &[b"abc", b"defg", b""];
        // 1 + 2 + 0 = 3
        assert_eq!(approx_tokens_total(buffers.iter().copied()), 3);
    }
}
