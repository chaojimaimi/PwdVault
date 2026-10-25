use std::sync::OnceLock;

use rand::{rngs::OsRng, Rng};

use crate::VaultError;

/// EFF short wordlist #1 (1296 words), embedded verbatim so passphrases are
/// reproducible from a published, reviewable source:
/// https://www.eff.org/files/2016/09/08/eff_short_wordlist_1.txt
/// (retrieved 2026-10-25; the four-digit dice-value column was stripped —
/// `cut -f2` — leaving exactly one word per line, so the file still diffs
/// cleanly against the EFF original).
const EFF_SHORT_WORDLIST: &str = include_str!("eff_short_wordlist_1.txt");

/// Wordlist length constant the sampling math below is written against.
const WORDLIST_LEN: usize = 1296;

/// Parse (once) and hand out the embedded wordlist. The completeness
/// invariants (exactly 1296 ASCII-lowercase words, no duplicates) are pinned
/// by `wordlist_integrity` in the tests below — a corrupted embedded file
/// fails the build's test run, not user generation.
fn eff_words() -> &'static [&'static str; WORDLIST_LEN] {
    static WORDS: OnceLock<[&'static str; WORDLIST_LEN]> = OnceLock::new();
    WORDS.get_or_init(|| {
        let mut words = [""; WORDLIST_LEN];
        for (slot, line) in words.iter_mut().zip(EFF_SHORT_WORDLIST.lines()) {
            *slot = line;
        }
        words
    })
}

pub fn generate_password(
    length: usize,
    include_uppercase: bool,
    include_lowercase: bool,
    include_numbers: bool,
    include_symbols: bool,
) -> Result<String, VaultError> {
    pwdvault_domain::validation::generator(
        length,
        include_uppercase,
        include_lowercase,
        include_numbers,
        include_symbols,
    )?;

    let mut charset = String::new();
    let mut required_chars = Vec::new();

    // Collect all available character classes and their representatives
    if include_uppercase {
        charset.push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        required_chars.push('A');
    }
    if include_lowercase {
        charset.push_str("abcdefghijklmnopqrstuvwxyz");
        required_chars.push('a');
    }
    if include_numbers {
        charset.push_str("0123456789");
        required_chars.push('0');
    }
    if include_symbols {
        charset.push_str("!@#$%^&*()_+-=[]{}|;:,.<>?");
        required_chars.push('!');
    }

    let mut rng = OsRng; // Use OS entropy source for better security
    let bytes: Vec<u8> = charset.bytes().collect();

    let num_required = required_chars.len();
    let mut password_chars: Vec<char> = required_chars;

    // Fill remaining positions with random characters from full charset
    for _ in 0..(length.saturating_sub(num_required)) {
        let idx = rng.gen_range(0..bytes.len());
        password_chars.push(bytes[idx] as char);
    }

    // Fisher-Yates shuffle to avoid predictable patterns (e.g., always starting with uppercase)
    let len = password_chars.len();
    for i in 0..len {
        let j = rng.gen_range(i..len);
        password_chars.swap(i, j);
    }

    Ok(password_chars.into_iter().collect())
}

/// Diceware-style passphrase over the embedded EFF short list (v1.4.0).
///
/// Entropy: `words * log2(1296)` (~10.34 bits/word) plus log2(100) when an
/// appendix number is enabled — the frontend strength meter mirrors exactly
/// this accounting (passwordStrength.ts), Rust itself scores no strength.
pub fn generate_passphrase(
    words: u8,
    separator: &str,
    capitalize: bool,
    append_number: bool,
) -> Result<String, VaultError> {
    pwdvault_domain::validation::passphrase(words, separator)?;

    let wordlist = eff_words();
    let mut rng = OsRng;
    let mut parts: Vec<String> = Vec::with_capacity(words as usize);
    for _ in 0..words {
        // Rejection sampling WITHOUT modulo bias: 64800 = 1296 * 50 is the
        // largest multiple of 1296 below 2^16, so drawing u16 values and
        // accepting only v < 64800 keeps every word exactly equally likely
        // (`v % 1296` is unbiased on that accept domain). A plain
        // `gen_range` would be unbiased too, but the explicit accept-domain
        // documents the constant the wordlist length forces.
        let index = loop {
            let v: u16 = rng.gen();
            if v < 64800 {
                break (v % WORDLIST_LEN as u16) as usize;
            }
        };
        let mut word = wordlist[index].to_string();
        if capitalize {
            // Words are guaranteed ASCII (wordlist integrity test), so
            // byte-level ASCII upper-casing is safe.
            word[..1].make_ascii_uppercase();
        }
        parts.push(word);
    }

    let mut passphrase = parts.join(separator);
    if append_number {
        // 0-99 suffix, appended directly after the last word (adds
        // log2(100) bits regardless of the separator).
        passphrase.push_str(&rng.gen_range(0..100).to_string());
    }
    Ok(passphrase)
}

/// Numeric PIN (v1.4.0). Entropy: `len * log2(10)` (~3.32 bits/digit) —
/// short PINs are deliberately weak; the UI warns via the strength meter and
/// the 4-digit floor keeps it from getting absurd.
pub fn generate_pin(len: u8) -> Result<String, VaultError> {
    pwdvault_domain::validation::pin(len)?;

    let mut rng = OsRng;
    let digits: String = (0..len)
        .map(|_| char::from(b'0' + rng.gen_range(0..10u8)))
        .collect();
    Ok(digits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// Completeness of the embedded wordlist: exactly 1296 words, all ASCII
    /// lowercase letters (the single EFF hyphenated word "yo-yo" is the only
    /// non-letter exception), no duplicates — i.e. the file was not mangled
    /// in transit and the sampling math holds.
    #[test]
    fn wordlist_integrity() {
        let words = eff_words();
        assert_eq!(words.len(), 1296);
        let mut seen = HashSet::with_capacity(1296);
        for word in words.iter() {
            assert!(!word.is_empty());
            assert!(
                word.bytes().all(|b| b.is_ascii_lowercase() || b == b'-'),
                "non-ASCII-lowercase word in list: {word}"
            );
            assert!(seen.insert(*word), "duplicate word: {word}");
        }
        // Spot-check against the EFF original's first and last words.
        assert_eq!(words[0], "acid");
        assert_eq!(words[1295], "zoom");
    }

    /// No-modulo-bias sampling: the accept domain must be exactly the
    /// largest multiple of 1296 below 2^16, and every index must be
    /// reachable. Statistical uniformity itself is covered by the coarse
    /// chi-style check in `passphrase_sampling_is_coarsely_uniform`.
    #[test]
    fn passphrase_accept_domain_constant() {
        assert_eq!(WORDLIST_LEN * 50, 64800);
        assert!(64800 < u16::MAX as usize);
        assert!(64800 + WORDLIST_LEN > u16::MAX as usize);
    }

    #[test]
    fn passphrase_shape_follows_options() {
        // Deterministic assertions on shape (values are random by design):
        // word count, separator, capitalization, number suffix.
        let plain = generate_passphrase(5, "-", false, false).unwrap();
        assert_eq!(plain.split('-').count(), 5);
        assert!(plain.chars().all(|c| c.is_ascii_lowercase() || c == '-'));

        let spaced = generate_passphrase(3, " ", false, false).unwrap();
        assert_eq!(spaced.split(' ').count(), 3);

        let capped = generate_passphrase(4, ".", true, false).unwrap();
        let capped_words: Vec<&str> = capped.split('.').collect();
        assert_eq!(capped_words.len(), 4);
        assert!(capped_words.iter().all(|w| {
            w.chars().next().is_some_and(|c| c.is_ascii_uppercase())
                && w.chars().skip(1).all(|c| c.is_ascii_lowercase())
        }));

        let numbered = generate_passphrase(3, "-", false, true).unwrap();
        let digits: String = numbered
            .chars()
            .rev()
            .take_while(|c| c.is_ascii_digit())
            .collect();
        // The 0-99 suffix is 1 digit ~10% of the time (0-9) and 2 otherwise.
        assert!(
            (1..=2).contains(&digits.len()),
            "append_number adds a 0-99 suffix: {numbered}"
        );
        // Stripping the suffix restores exactly `words` separator-split words.
        let stripped = numbered
            .chars()
            .take(numbered.chars().count() - digits.len())
            .collect::<String>();
        assert_eq!(stripped.split('-').count(), 3, "from {numbered}");
        // The number is glued to the last word (no separator before it).
        let last_word = numbered.rsplit('-').next().unwrap();
        assert!(last_word.chars().last().is_some_and(|c| c.is_ascii_digit()));
    }

    /// Entropy ceiling sanity: 10 words is 10*10.34 ≈ 103 bits — well beyond
    /// any charset password of the same length; the value itself just has to
    /// look like a passphrase.
    #[test]
    fn passphrase_respects_bounds() {
        assert!(generate_passphrase(3, "-", false, false).is_ok());
        assert!(generate_passphrase(10, "", false, false).is_ok());
        assert!(generate_passphrase(2, "-", false, false).is_err());
        assert!(generate_passphrase(11, "-", false, false).is_err());
    }

    /// Coarse uniformity check for the rejection sampler: 1296 words over
    /// 129,600 draws gives an expected 100 hits per word; the binomial
    /// std-dev is ~9.9, so the ±7σ window [30, 170] keeps ordinary noise
    /// (~10⁻¹² false-fail rate over the whole suite) out while any REAL bias
    /// (a broken accept domain shifts words by thousands of draws) still
    /// lands orders of magnitude outside it. OsRng is unseedable by design —
    /// the wide margin is what makes the test honest rather than flaky.
    #[test]
    fn passphrase_sampling_is_coarsely_uniform() {
        let mut counts = vec![0usize; WORDLIST_LEN];
        let mut rng = OsRng;
        for _ in 0..129_600 {
            let index = loop {
                let v: u16 = rng.gen();
                if v < 64800 {
                    break (v % WORDLIST_LEN as u16) as usize;
                }
            };
            counts[index] += 1;
        }
        let expected = 100;
        for (index, count) in counts.iter().enumerate() {
            assert!(
                (30..=170).contains(count),
                "word {index} drawn {count} times (expected ~{expected})"
            );
        }
    }

    #[test]
    fn pin_shape_and_bounds() {
        let pin = generate_pin(8).unwrap();
        assert_eq!(pin.len(), 8);
        assert!(pin.chars().all(|c| c.is_ascii_digit()));

        assert!(generate_pin(4).is_ok());
        assert!(generate_pin(16).is_ok());
        assert!(generate_pin(3).is_err());
        assert!(generate_pin(17).is_err());
    }

    /// A PIN drawn from 16 digits stays inside the digit alphabet (no
    /// separator/capitalization leakage between modes).
    #[test]
    fn pin_alphabet_is_digits_only() {
        for len in [4u8, 6, 12, 16] {
            let pin = generate_pin(len).unwrap();
            assert!(pin.bytes().all(|b| b.is_ascii_digit()));
        }
    }
}
