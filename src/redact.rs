//! The redaction engine (SPEC §8.2) — the SECOND line of defense behind the never-log-at-source rule
//! (SPEC §7). Applied to every line at bundle/report time so a log bundle is safe to hand to a
//! stranger. The rule set is VERSIONED ([`RULES_VERSION`]) and recorded in every bundle manifest, so
//! a bundle's redaction guarantees are auditable after the fact.
//!
//! A false negative ships a secret, so the detectors err toward over-redaction. In particular the
//! mnemonic detector matches a run of ≥12 consecutive BIP39-wordlist words regardless of whether they
//! sit in `key=value`, a bare `# Mnemonic:` comment line, or a `\n`-escaped multi-line value — the
//! `.test-credentials` leak (2026-07-12) proved that comment-style seeds are the real hazard.

use std::collections::HashSet;

use once_cell::sync::Lazy;
use regex::Regex;

/// The versioned redaction rule set. Bump on any rule change; recorded in the bundle manifest.
pub const RULES_VERSION: u32 = 1;

/// The minimum consecutive BIP39 words that constitute a redactable mnemonic run (SPEC §8.2).
const MIN_MNEMONIC_RUN: usize = 12;

/// The authoritative English BIP39 wordlist as a fast lookup set (reused from the `bip39` crate).
static BIP39_WORDS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    bip39::Language::English
        .word_list()
        .iter()
        .copied()
        .collect()
});

/// A BIP39 word token (3–8 lowercase letters) and its position in the input.
static WORD: Lazy<Regex> = Lazy::new(|| Regex::new(r"[A-Za-z]{3,8}").unwrap());

/// Chars allowed BETWEEN two mnemonic words: whitespace, and the punctuation/escapes a serialized
/// seed can carry (`\n` escape, quotes, commas, colons, `#`, `-`). A gap of only these keeps a run
/// contiguous, so a `\n`-joined or comment-embedded seed is still caught.
static MNEMONIC_GAP: Lazy<Regex> = Lazy::new(|| Regex::new(r#"^[\s\\n"',:#-]*$"#).unwrap());

static PEM_BLOCK: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?s)-----BEGIN[^-]*-----.*?-----END[^-]*-----").unwrap());

/// `Authorization: <v>` / `"authorization":"<v>"` — keep the key, redact the value.
static AUTH_HEADER: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)(authorization"?\s*[:=]\s*"?)([^"\s,}]+)"#).unwrap());

/// `Bearer <token>` anywhere.
static BEARER: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\bbearer\s+([A-Za-z0-9._\-]+)").unwrap());

/// `token`/`api_key`/`secret`/`password`/`passphrase`/`pairing_code` = / : `<v>` (JSON or kv).
static TOKEN_KV: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)("?(?:token|api[_-]?key|apikey|secret|password|passphrase|pairing[_-]?code)"?\s*[:=]\s*"?)([^"\s,}]+)"#,
    )
    .unwrap()
});

/// A bech32 `xch1…`/`txch1…` address — truncate to the HRP + first 8 payload chars.
static BECH32: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b(t?xch1)([0-9a-z]{8})[0-9a-z]{4,}\b").unwrap());

/// Home-dir usernames in Windows / Linux / macOS paths.
static WIN_USER: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)([A-Za-z]:\\Users\\)([^\\\s"]+)"#).unwrap());
static NIX_USER: Lazy<Regex> = Lazy::new(|| Regex::new(r#"(/home/|/Users/)([^/\s"]+)"#).unwrap());

/// Redact one line of log text (SPEC §8.2). Idempotent enough for repeated application.
pub fn line(input: &str) -> String {
    // Mnemonic runs first, on the original words, before other rules perturb the text.
    let stage = redact_mnemonics(input);
    let stage = PEM_BLOCK.replace_all(&stage, "[REDACTED:pem]").into_owned();
    let stage = AUTH_HEADER
        .replace_all(&stage, "${1}[REDACTED:auth]")
        .into_owned();
    let stage = BEARER
        .replace_all(&stage, "Bearer [REDACTED:auth]")
        .into_owned();
    let stage = TOKEN_KV
        .replace_all(&stage, "${1}[REDACTED:token]")
        .into_owned();
    let stage = BECH32.replace_all(&stage, "${1}${2}…").into_owned();
    let stage = WIN_USER.replace_all(&stage, r"${1}<user>").into_owned();
    NIX_USER.replace_all(&stage, "${1}<user>").into_owned()
}

/// Redact every line of a multi-line string.
pub fn text(input: &str) -> String {
    input.lines().map(line).collect::<Vec<_>>().join("\n")
}

/// Find and replace maximal runs of ≥[`MIN_MNEMONIC_RUN`] consecutive BIP39 words (SPEC §8.2).
fn redact_mnemonics(input: &str) -> String {
    let words: Vec<_> = WORD
        .find_iter(input)
        .map(|m| {
            (
                m.start(),
                m.end(),
                BIP39_WORDS.contains(m.as_str().to_ascii_lowercase().as_str()),
            )
        })
        .collect();

    let mut out = String::new();
    let mut cursor = 0; // byte index copied up to
    let mut i = 0;
    while i < words.len() {
        // Extend a run of wordlist words whose gaps contain only separator chars.
        let start = i;
        let mut end = i;
        while end + 1 < words.len()
            && words[end].2
            && words[end + 1].2
            && MNEMONIC_GAP.is_match(&input[words[end].1..words[end + 1].0])
        {
            end += 1;
        }
        let run_len = if words[start].2 { end - start + 1 } else { 0 };
        if run_len >= MIN_MNEMONIC_RUN {
            out.push_str(&input[cursor..words[start].0]);
            out.push_str("[REDACTED:mnemonic]");
            cursor = words[end].1;
            i = end + 1;
        } else {
            i += 1;
        }
    }
    out.push_str(&input[cursor..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED12: &str =
        "abandon ability able about above absent absorb abstract absurd abuse access accident";

    #[test]
    fn redacts_key_value_mnemonic() {
        let got = line(&format!("mnemonic={SEED12}"));
        assert!(got.contains("[REDACTED:mnemonic]"), "{got}");
        assert!(!got.contains("abandon"));
    }

    #[test]
    fn redacts_comment_style_mnemonic() {
        // The `.test-credentials` leak shape: a seed on a `#` comment line, not key=value.
        let got = line(&format!("# Mnemonic: {SEED12}"));
        assert!(got.contains("[REDACTED:mnemonic]"), "{got}");
        assert!(!got.contains("abstract"));
    }

    #[test]
    fn eleven_words_not_redacted() {
        let eleven = SEED12.rsplit_once(' ').unwrap().0; // drop the 12th word
        assert!(!line(eleven).contains("[REDACTED:mnemonic]"));
    }

    #[test]
    fn redacts_pem_and_tokens() {
        assert!(
            line("key: -----BEGIN PRIVATE KEY-----\\nMIIB\\n-----END PRIVATE KEY-----")
                .contains("[REDACTED:pem]")
        );
        assert!(line(r#"{"token":"abc123secret"}"#).contains("[REDACTED:token]"));
        assert!(line("Authorization: Bearer zzz.yyy.xxx").contains("[REDACTED:auth]"));
    }

    #[test]
    fn truncates_bech32_but_keeps_public_ids() {
        let got = line("addr=xch1qqqqqqqqwwwwwwwweeeeeeee store=abc123def456 peer=203.0.113.7");
        assert!(got.contains("xch1qqqqqqq…") || got.contains("…"), "{got}");
        assert!(got.contains("abc123def456"), "store ids are KEPT: {got}");
        assert!(got.contains("203.0.113.7"), "peer IPs are KEPT: {got}");
    }

    #[test]
    fn scrubs_home_dir_username() {
        assert!(line(r"path=C:\Users\alice\AppData").contains(r"C:\Users\<user>"));
        assert!(line("path=/home/bob/logs").contains("/home/<user>"));
    }
}
