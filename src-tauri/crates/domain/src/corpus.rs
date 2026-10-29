//! Weak-password corpus layer (v1.7.0 WP1).
//!
//! One shared algorithm ported across the three runtimes (fix_impl_plan
//! v1.7.0.md §3, Appendix B): the frontend display layer (`weakCorpus.ts`,
//! `weak-corpus.js`) mirrors these three lookups entry for entry, and the
//! extension-side sync guard pins all three copies equal. Three independent
//! checks, any hit ⇒ the password is weak regardless of its zxcvbn score:
//!
//! 1. `corpus_exact_hit` — the whole lowercase password is a corpus entry.
//! 2. `corpus_normalized_hit` — same after the vowel-position leet mapping
//!    (`@4→a 0→o 3→e $5→s 7+→t`; `1` and `!` deliberately NOT mapped, so
//!    digit/symbol suffixes are not welded into letters).
//! 3. `core_word_formula_hit` — a curated core word appears with a
//!    non-letter on its left (or string start), no letters between its end
//!    and the string end, and the password mixes in at least one digit or
//!    symbol ("password1!", "Admin@123", normalized "password123").
//!
//! The corpus is the frozen `weak_passwords.txt` next to this file (Appendix
//! A contract: printable ASCII, length ≥ 4, lowercase, deduped, no
//! whitespace, no leading-`#` entries; 9952 entries (incl. the famous-form anchor p@ssw0rd123) + a `#` comment header).
//! It is embedded at compile time and parsed once.

use std::collections::HashSet;
use std::sync::OnceLock;

/// The corpus file, one entry per line with a `#` comment header.
/// WP3's corpus-sync guard pins this file's entry set equal to the TS/JS
/// copies — do not edit it without syncing all three.
const CORPUS_RAW: &str = include_str!("weak_passwords.txt");

/// Curated core words (Appendix B, ~70 words). A match against these under
/// the boundary rules below is a weak verdict on its own. The exclusion list
/// in the plan (latest, rocket, quick, brown, correct, horse, battery,
/// staple, troubador) is pinned by a unit test — none of these may ever
/// join this table, they are the false-positive sentinels' carriers.
const CORE_WORDS: [&str; 72] = [
    "password",
    "passwd",
    "pass",
    "admin",
    "root",
    "user",
    "guest",
    "test",
    "login",
    "qwerty",
    "welcome",
    "hello",
    "love",
    "sunshine",
    "princess",
    "dragon",
    "monkey",
    "master",
    "superman",
    "batman",
    "football",
    "baseball",
    "basketball",
    "soccer",
    "hockey",
    "shadow",
    "michael",
    "jordan",
    "charlie",
    "andrew",
    "daniel",
    "jessica",
    "pepper",
    "hunter",
    "ranger",
    "harley",
    "buster",
    "killer",
    "george",
    "freedom",
    "whatever",
    "ninja",
    "money",
    "happy",
    "secret",
    "access",
    "flower",
    "summer",
    "winter",
    "angel",
    "magic",
    "phoenix",
    "knight",
    "warrior",
    "samsung",
    "apple",
    "google",
    "computer",
    "internet",
    "service",
    "starwars",
    "letmein",
    "trustno1",
    "azerty",
    "iloveyou",
    "family",
    "online",
    // Chinese-context classics (leak-era romaji).
    "woaini",
    "wodeaini",
    "mima",
    "wodemima",
    "jiayou",
];

/// Vowel-position leet mapping (Appendix B, three-end constant). `1` and `!`
/// are intentionally absent so unmapped suffix digits can't be welded into
/// letters. NOTE: `3→e` IS in the pinned table, so digit suffixes containing
/// a 3 DO get welded ("P@ssw0rd123" → "password12e") — the plan's worked
/// example for that vector assumed `3` unmapped; the table is the normative
/// three-end constant and wins (defect recorded in the WP1 report).
fn normalize(password: &str) -> String {
    password
        .to_lowercase()
        .chars()
        .map(|c| match c {
            '@' | '4' => 'a',
            '0' => 'o',
            '3' => 'e',
            '$' | '5' => 's',
            '7' | '+' => 't',
            other => other,
        })
        .collect()
}

/// Parse the embedded corpus once. `str::lines` already strips a trailing
/// `\r` from `\r\n` pairs; comment and blank lines are skipped per the
/// Appendix A format.
fn corpus_set() -> &'static HashSet<&'static str> {
    static SET: OnceLock<HashSet<&'static str>> = OnceLock::new();
    SET.get_or_init(|| {
        CORPUS_RAW
            .lines()
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .collect()
    })
}

/// The composed corpus-layer gate: any of the three checks hitting makes the
/// password weak (fix_impl_plan v1.7.0.md §2, "Rust weak verdict =
/// corpus_hit(password) OR zxcvbn ≤ 2").
pub fn corpus_hit(password: &str) -> bool {
    corpus_exact_hit(password) || corpus_normalized_hit(password) || core_word_formula_hit(password)
}

/// Check 1: the whole lowercase password is a corpus entry.
pub fn corpus_exact_hit(password: &str) -> bool {
    corpus_set().contains(password.to_lowercase().as_str())
}

/// Check 2: the whole vowel-position-normalized password is a corpus entry
/// (P@ssw0rd → "password" → hit; Adm0n123 → "admin123" → hit).
pub fn corpus_normalized_hit(password: &str) -> bool {
    corpus_set().contains(normalize(password).as_str())
}

/// Check 3: a core word with a non-letter on its left (or at string start)
/// whose match runs to the end of the letter content — i.e. from the match
/// end to the string end only digits/symbols may follow — in the raw
/// lowercase OR the normalized form, with the original password mixing in at
/// least one digit or symbol.
///
/// The boundaries are the false-positive defense (Appendix B): "latest#Rocket9"
/// embeds "test" but its left neighbor is a letter, and "testabc123" is
/// rejected by the right-boundary rule. The search uses first-occurrence
/// `indexOf` semantics per form, exactly like the TS/JS ports.
pub fn core_word_formula_hit(password: &str) -> bool {
    // A pure-letter password can never satisfy the formula: the gate also
    // keeps ASCII-letter-scoped scanning consistent with the boundary rules
    // (the corpus and core words are ASCII-only).
    if !password.chars().any(|c| !c.is_ascii_alphabetic()) {
        return false;
    }
    let raw_lower = password.to_lowercase();
    let normalized = normalize(password);
    CORE_WORDS
        .iter()
        .any(|word| hits_form(&raw_lower, word) || hits_form(&normalized, word))
}

/// One core word against one form of the password. JS `indexOf` parity:
/// only the FIRST occurrence of the word is examined.
fn hits_form(form: &str, word: &str) -> bool {
    let Some(pos) = form.find(word) else {
        return false;
    };
    // Left boundary: the character before the match must not be an ASCII
    // letter (string start counts as a boundary).
    let left_neighbor_is_letter = form[..pos]
        .chars()
        .next_back()
        .is_some_and(|c| c.is_ascii_alphabetic());
    // Right boundary: no ASCII letters between the match end and the string
    // end — a word followed by more letters is just prose ("testabc123").
    let right_tail_has_letter = form[pos + word.len()..]
        .chars()
        .any(|c| c.is_ascii_alphabetic());
    !left_neighbor_is_letter && !right_tail_has_letter
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corpus_parses_to_9952_entries_without_comments_or_blanks() {
        let set = corpus_set();
        assert_eq!(set.len(), 9952, "corpus entry count drifted");
        assert!(set.contains("a123456"));
        assert!(set.contains("1qaz2wsx"));
        // The famous-forms anchor added after WP1 (post-anchor sync fix).
        assert!(set.contains("p@ssw0rd123"));
        // Comment header lines and blanks must never become entries.
        assert!(!set.iter().any(|entry| entry.starts_with('#')));
        assert!(!set.contains(""));
    }

    #[test]
    fn exact_hit_is_case_insensitive_full_string_membership() {
        assert!(corpus_exact_hit("a123456"));
        assert!(corpus_exact_hit("Admin123"));
        assert!(!corpus_exact_hit(""));
        // The famous-forms anchor: exact match is lowercase-insensitive, so
        // any letter-casing of P@ssw0rd123 hits (Appendix B pinned vector).
        assert!(corpus_exact_hit("p@ssw0rd123"));
        assert!(corpus_exact_hit("P@ssw0rd123"));
    }

    #[test]
    fn normalized_hit_maps_leet_vowel_positions_only() {
        // @→a, 0→o: P@ssw0rd normalizes to "password" (a corpus entry) while
        // its exact lowercase form is not one.
        assert!(!corpus_exact_hit("P@ssw0rd"));
        assert!(corpus_normalized_hit("P@ssw0rd"));
        // Same for the $/5→s mapping: 5unshine normalizes to "sunshine".
        // (The sample must avoid unmappable digits in the target: 3→e also
        // welds, so "Adm0n123" lands on "admin12e", not "admin123".)
        assert!(!corpus_exact_hit("5unshine"));
        assert!(corpus_normalized_hit("5unshine"));
        // 1 and ! are NOT mapped: "password1!" stays "password1!" (∉ corpus).
        assert!(!corpus_normalized_hit("password1!"));
        // PLAN DEFECT (recorded in the WP1 completion report): under the
        // pinned table 3→e, "P@ssw0rd123" normalizes to "password12e" — the
        // trailing 3 is welded into a letter — so Appendix B's original
        // mechanism annotation ("normalized password123, digit-only right
        // boundary") does not hold. The vector is carried by corpus EXACT via
        // the famous-forms anchor (see weak_passwords.txt) + zxcvbn (score 1).
        assert_eq!(normalize("P@ssw0rd123"), "password12e");
        assert!(!corpus_normalized_hit("P@ssw0rd123"));
    }

    #[test]
    fn core_word_formula_boundary_cases() {
        // Hits: word at the boundary, digit/symbol-only tail.
        assert!(core_word_formula_hit("Admin@123"));
        assert!(core_word_formula_hit("password1!"));
        assert!(core_word_formula_hit("sunshine123"));
        assert!(core_word_formula_hit("qwerty!@#"));
        // Dual-form search: the raw form catches "Admin@123"; for "P@ssw0rd"
        // the raw "pass" hit is prose-blocked ("@ssw0rd" has letters) and the
        // normalized form "password" supplies the hit.
        assert!(core_word_formula_hit("P@ssw0rd"));
        // PLAN DEFECT (see normalized_hit test): under the pinned mapping
        // (3→e) "P@ssw0rd123" normalizes to "password12e", whose letter tail
        // defeats the right-boundary rule — the formula does NOT fire. The
        // vector classifies Weak via zxcvbn (score 1).
        assert!(!core_word_formula_hit("P@ssw0rd123"));
        // Left boundary: "test" embedded after a letter is prose.
        assert!(!core_word_formula_hit("xtests123"));
        // Right boundary: a word followed by letters is prose.
        assert!(!core_word_formula_hit("testabc123"));
        // The gate: a pure-letter password never satisfies the formula even
        // with a perfect boundary match.
        assert!(!core_word_formula_hit("test"));
        // Pure digits: no core word can match.
        assert!(!core_word_formula_hit("1234567890"));
        // Chinese input: corpus is ASCII-only, no core word matches.
        assert!(!corpus_exact_hit("一二三四五六七八九十"));
        assert!(!corpus_normalized_hit("一二三四五六七八九十"));
        assert!(!core_word_formula_hit("一二三四五六七八九十"));
        // Empty string: no hit on any check.
        assert!(!corpus_exact_hit(""));
        assert!(!corpus_normalized_hit(""));
        assert!(!core_word_formula_hit(""));
    }

    #[test]
    fn false_positive_sentinels_miss_all_three_checks() {
        // Appendix B sentinels — every check must stay silent, including the
        // normalized forms (verified against the corpus file itself).
        for sentinel in ["latest#Rocket9", "7hE-qu1ck-b0wnes"] {
            assert!(!corpus_exact_hit(sentinel), "{sentinel:?}");
            assert!(!corpus_normalized_hit(sentinel), "{sentinel:?}");
            assert!(!core_word_formula_hit(sentinel), "{sentinel:?}");
            assert!(!corpus_hit(sentinel), "{sentinel:?}");
        }
    }

    #[test]
    fn all_freeze_table_sentinels_are_absent_from_the_corpus() {
        // Appendix A build-time check: sentinels (lowercase AND normalized)
        // must not be corpus entries, or the "not weak" pins would flip.
        for (sentinel, normalized) in [
            ("kx9$mp2!vl5#nq8@wr4&jf7^", "kx9smp2!vl5s#nq8awra&jft^"),
            ("correcthorsebatterystaple", "correcthorsebatterystaple"),
            ("d7g!klm9@pq2", "dtg!klm9apq2"),
            ("latest#rocket9", "latest#rocket9"),
            ("7he-qu1ck-b0wnes", "the-qu1ck-bownes"),
        ] {
            assert!(!corpus_exact_hit(sentinel), "{sentinel:?}");
            assert!(!corpus_normalized_hit(normalized), "{normalized:?}");
        }
    }

    #[test]
    fn excluded_words_never_join_the_core_word_table() {
        // The plan's sentinel-defense exclusion list. These words carry the
        // false-positive sentinels; adding any of them breaks Appendix B.
        for excluded in [
            "latest",
            "rocket",
            "quick",
            "brown",
            "correct",
            "horse",
            "battery",
            "staple",
            "troubador",
        ] {
            assert!(
                !CORE_WORDS.contains(&excluded),
                "excluded word {excluded:?} leaked into CORE_WORDS"
            );
        }
    }

    #[test]
    fn composed_gate_reports_corpus_entries_and_formula_hits() {
        assert!(corpus_hit("woaini520")); // exact (Chinese supplement)
        assert!(corpus_hit("Admin@123")); // core-word formula (raw form)
        assert!(corpus_hit("P@ssw0rd")); // normalized exact ("password")
        assert!(corpus_hit("P@ssw0rd123")); // EXACT via the famous-forms anchor
                                            // (normalization still misses it: 3→e
                                            // welds the tail into password12e)
        assert!(!corpus_hit("correcthorsebatterystaple"));
    }
}
