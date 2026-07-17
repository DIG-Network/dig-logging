//! The redaction engine (SPEC §8.2) — the SECOND line of defense behind the never-log-at-source rule
//! (SPEC §7). Applied to every line at BUNDLE time ([`bundle::build`](crate::bundle) re-redacts the
//! on-disk JSONL as it is zipped) so a log bundle is safe to hand to a stranger. It is NOT applied at
//! write time — the on-disk log files hold RAW lines, and `logs tail`/a manual copy therefore see
//! un-redacted text. The primary defense is source-discipline (SPEC §7, the never-log list); bundle
//! redaction is the guaranteed chokepoint for anything sent off-box. The rule set is VERSIONED
//! ([`RULES_VERSION`]) and recorded in every bundle manifest, so a bundle's redaction guarantees are
//! auditable after the fact.
//!
//! A false negative ships a secret, so the detectors err toward over-redaction — with ONE deliberate
//! exception: key detection is FIELD-NAME-driven, never a blanket "32-byte hex = secret" heuristic,
//! because storeIds, rootHashes, coinIds, puzzle hashes, and peer IPs are ALSO high-entropy hex/base64
//! and are KEPT (they are public and load-bearing for debugging, SPEC §8.2). A field whose NAME marks
//! it secret (`*_key`/`*_secret`/`sk`/`xprv`/`wif`/`seed`/`mnemonic`/…) has its value redacted; a
//! field on the known-safe list ([`SAFE_KEY_NAMES`]) is always kept even when its name ends `_key`
//! (e.g. `resource_key`). The mnemonic detector matches a run of ≥12 consecutive BIP39-wordlist words
//! regardless of whether they sit in `key=value`, a bare `# Mnemonic:` comment line, a numbered
//! `1. abandon 2. ability …` layout, or a `\n`-escaped multi-line value — the `.test-credentials`
//! leak (2026-07-12) proved that comment-style seeds are the real hazard. Non-English BIP39 wordlists
//! are an accepted residual (English-only), documented in SPEC §8.2.

use std::collections::HashSet;

use once_cell::sync::Lazy;
use regex::Regex;

/// The versioned redaction rule set. Bump on any rule change; recorded in the bundle manifest.
///
/// v2 added field-name-driven private-key/seed redaction ([`SENSITIVE_KV`], [`KEY_PHRASE`]) and
/// numbered-mnemonic detection, over v1's PEM + token/auth + narrow mnemonic set.
pub const RULES_VERSION: u32 = 3;

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
/// seed can carry (`\n` escape, quotes, commas, colons, `#`, `-`, and the digits/`.`/`)` of a
/// NUMBERED `1. abandon 2. ability …` layout). A gap of only these keeps a run contiguous, so a
/// `\n`-joined, comment-embedded, or numbered seed is still caught as one run.
static MNEMONIC_GAP: Lazy<Regex> = Lazy::new(|| Regex::new(r#"^[\s\\n"',:#.)(0-9-]*$"#).unwrap());

static PEM_BLOCK: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?s)-----BEGIN[^-]*-----.*?-----END[^-]*-----").unwrap());

/// `Authorization: <v>` / `"authorization":"<v>"` — keep the key, redact the value.
/// Handles both `Authorization: Bearer <token>` and bare `Authorization: <opaque>` forms,
/// consuming the Bearer scheme + token together so the full credential is redacted.
static AUTH_HEADER: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(authorization"?\s*[:=]\s*"?)((?:[Bb]earer\s+)?[A-Za-z0-9._\-]+)"#).unwrap()
});

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

/// Field names that are HIGH-ENTROPY but PUBLIC and load-bearing for debugging, so their values are
/// KEPT even though the name may end `_key` (SPEC §8.2 KEEP list). When in doubt a name is treated as
/// sensitive (a missed key leaks custody; a false-scrub of one of these merely hampers debugging), so
/// this list is the explicit allow-list that overrides the `_key`/`_secret` suffix rule.
static SAFE_KEY_NAMES: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        "store_id",
        "storeid",
        "store",
        "root",
        "root_hash",
        "roothash",
        "coin_id",
        "coinid",
        "coin",
        "puzzle_hash",
        "owner_puzzle_hash",
        "peer",
        "peer_id",
        "addr",
        "address",
        "ip",
        "generation",
        "capsule",
        "resource_key",
        "port",
        "public_key",
        "pubkey",
        "verifying_key",
    ]
    .into_iter()
    .collect()
});

/// Field names whose VALUE is always a secret regardless of suffix (kv or JSON). The `_key`/`_secret`
/// suffix and `seed`/`mnemonic`/`priv` substrings extend this in [`is_sensitive_key`].
const SENSITIVE_EXACT: &[&str] = &[
    "sk",
    "xprv",
    "wif",
    "seed",
    "mnemonic",
    "private_key",
    "secret_key",
    "signing_key",
    "beacon_key",
    "privkey",
    "secretkey",
];

/// Any `name = value` / `name: value` / JSON `"name":"value"` pair — the value is redacted ONLY when
/// the NAME marks it secret ([`is_sensitive_key`]); every other pair is left untouched. This is the
/// field-name-driven key rule that catches `private_key`/`signing_key`/`sk`/`xprv`/`wif`/`seed`/
/// `beacon_key`/`*_key`/`*_secret` (incl. raw base64/hex values) WITHOUT blanket-scrubbing public
/// high-entropy ids. Group 1 = optional open quote, 2 = name, 3 = separator, 4 = value.
static SENSITIVE_KV: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)("?)([A-Za-z][A-Za-z0-9_]*)("?\s*[:=]\s*"?)([^"\s,}]+)"#).unwrap()
});

/// A bare prose reference `<kind> key <hex-or-base64>` (e.g. `loaded signing key <hex>`), which no
/// kv rule would catch. Group 1 = the `<kind> key` phrase (kept), group 2 = the secret material.
static KEY_PHRASE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b((?:signing|private|secret|beacon)\s+key)\s+([A-Za-z0-9+/]{16,}={0,2})")
        .unwrap()
});

/// Is a field NAME one whose value must be redacted? Safe public ids ([`SAFE_KEY_NAMES`]) win first;
/// then exact sensitive names, the `_key`/`_secret` suffix, and `seed`/`mnemonic`/`priv` substrings.
fn is_sensitive_key(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    if SAFE_KEY_NAMES.contains(name.as_str()) {
        return false;
    }
    SENSITIVE_EXACT.contains(&name.as_str())
        || name.ends_with("_key")
        || name.ends_with("_secret")
        || name.contains("seed")
        || name.contains("mnemonic")
        || name.contains("priv")
}

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
    let stage = KEY_PHRASE
        .replace_all(&stage, "${1} [REDACTED:key]")
        .into_owned();
    // Field-name-driven key redaction: redact a value ONLY when its NAME is secret, and never
    // re-touch an already-redacted value (so a prior token/auth rule keeps its `:token`/`:auth` kind).
    let stage = SENSITIVE_KV
        .replace_all(&stage, |caps: &regex::Captures| {
            let value = &caps[4];
            if is_sensitive_key(&caps[2]) && !value.starts_with("[REDACTED") {
                format!("{}{}{}[REDACTED:key]", &caps[1], &caps[2], &caps[3])
            } else {
                caps[0].to_string()
            }
        })
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
        // PEM block redaction
        let pem_out = line("key: -----BEGIN PRIVATE KEY-----\\nMIIB\\n-----END PRIVATE KEY-----");
        assert!(pem_out.contains("[REDACTED:pem]"), "pem: {pem_out}");
        assert!(!pem_out.contains("BEGIN"), "pem key leaked: {pem_out}");
        assert!(!pem_out.contains("MIIB"), "pem key leaked: {pem_out}");

        // JSON token field redaction
        let token_out = line(r#"{"token":"abc123secret"}"#);
        assert!(token_out.contains("[REDACTED:token]"), "token: {token_out}");
        assert!(
            !token_out.contains("abc123secret"),
            "token leaked: {token_out}"
        );

        // Authorization header with Bearer token (the main security leak case)
        let auth_out = line("Authorization: Bearer zzz.yyy.xxx");
        assert!(auth_out.contains("[REDACTED:auth]"), "auth: {auth_out}");
        assert!(
            !auth_out.contains("zzz.yyy.xxx"),
            "Bearer token leaked: {auth_out}"
        );
        assert!(
            !auth_out.contains("Bearer zzz"),
            "Bearer token leaked: {auth_out}"
        );

        // Bare Authorization header (non-Bearer form)
        let opaque_out = line("Authorization: opaque_token_abc123");
        assert!(
            opaque_out.contains("[REDACTED:auth]"),
            "opaque: {opaque_out}"
        );
        assert!(
            !opaque_out.contains("opaque_token_abc123"),
            "opaque token leaked: {opaque_out}"
        );

        // Standalone Bearer without Authorization prefix
        let bearer_out = line("Bearer eyJ.payload.sig");
        assert!(
            bearer_out.contains("[REDACTED:auth]"),
            "bearer: {bearer_out}"
        );
        assert!(
            !bearer_out.contains("eyJ.payload.sig"),
            "Bearer credential leaked: {bearer_out}"
        );
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

    // --- v2: field-name-driven private-key / seed redaction (SECURITY regressions, §2.2) ---

    /// Each named-key field must have its value redacted, in kv AND JSON shapes, while the FIELD
    /// NAME survives so the log stays diagnosable.
    #[test]
    fn redacts_named_key_and_seed_fields() {
        for name in [
            "private_key",
            "secret_key",
            "signing_key",
            "beacon_key",
            "sk",
            "xprv",
            "wif",
            "seed",
            "mnemonic",
        ] {
            let secret = "ZcjI14QiJ1Qety2clrKoDEkJyehiSBRoiYylEfiW3JI";
            let kv = line(&format!("{name}={secret}"));
            assert!(kv.contains("[REDACTED:key]"), "kv {name}: {kv}");
            assert!(!kv.contains(secret), "kv {name} leaked: {kv}");
            assert!(kv.contains(name), "kv {name} name dropped: {kv}");

            let json = line(&format!(r#"{{"{name}":"deadbeefdeadbeef01234567"}}"#));
            assert!(json.contains("[REDACTED:key]"), "json {name}: {json}");
            assert!(
                !json.contains("deadbeefdeadbeef01234567"),
                "json {name}: {json}"
            );
        }
    }

    /// The DIG identity / beacon key logged as bare prose, not a kv pair.
    #[test]
    fn redacts_bare_signing_key_phrase() {
        let got = line("loaded signing key 5f3a9c1b7e2d4088aa11bb22cc33dd44");
        assert!(got.contains("signing key [REDACTED:key]"), "{got}");
        assert!(!got.contains("5f3a9c1b7e2d4088"), "{got}");
    }

    /// A numbered `1. word 2. word …` seed layout is one redactable run.
    #[test]
    fn redacts_numbered_mnemonic() {
        let numbered = "1. abandon 2. ability 3. able 4. about 5. above 6. absent \
             7. absorb 8. abstract 9. absurd 10. abuse 11. access 12. accident";
        let got = line(numbered);
        assert!(got.contains("[REDACTED:mnemonic]"), "{got}");
        assert!(
            !got.contains("abandon") && !got.contains("accident"),
            "{got}"
        );
    }

    /// The KEEP guard: public high-entropy ids must NEVER be scrubbed even though a `_key` suffix or
    /// 32-byte hex would otherwise look secret — a false-scrub here breaks debugging (SPEC §8.2).
    #[test]
    fn keeps_public_ids_and_safe_named_fields() {
        let ids = concat!(
            "store_id=7d8f0a1b2c3d4e5f60718293a4b5c6d7 ",
            "root_hash=aabbccddeeff00112233445566778899 ",
            "coin_id=1122334455667788990011223344556677 ",
            "puzzle_hash=ec7c30deadbeefcafe0011223344556677 ",
            "resource_key=cafebabecafebabecafebabecafebabe ",
            "public_key=abc123def456abc123def456abc123 ",
            "peer=203.0.113.7 port=9257 generation=42"
        );
        let got = line(ids);
        assert!(
            !got.contains("[REDACTED"),
            "public ids over-scrubbed: {got}"
        );
        for kept in [
            "7d8f0a1b2c3d4e5f60718293a4b5c6d7",
            "aabbccddeeff00112233445566778899",
            "ec7c30deadbeefcafe0011223344556677",
            "cafebabecafebabecafebabecafebabe",
            "203.0.113.7",
            "9257",
        ] {
            assert!(got.contains(kept), "{kept} must be kept: {got}");
        }
    }

    /// A token/auth value keeps its precise `[REDACTED:token]`/`:auth` kind — the generic key rule
    /// must not re-label an already-redacted value.
    #[test]
    fn key_rule_does_not_relabel_prior_redaction() {
        let got = line(r#"{"api_key":"sekret","secret":"other"}"#);
        assert!(got.contains("[REDACTED:token]"), "{got}");
        assert!(!got.contains("[REDACTED:token][REDACTED"), "{got}");
        assert!(!got.contains("sekret") && !got.contains("other"), "{got}");
    }
}
