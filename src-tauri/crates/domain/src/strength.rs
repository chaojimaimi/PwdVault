//! Password strength scoring — Rust port of the frontend heuristic.
//!
//! WP1 (v1.5.0): the security dashboard aggregates weak-password findings on
//! the Rust side, so the same 0-100 heuristic must exist here. This module is
//! a FAITHFUL port of `getPasswordStrength` in `src/utils/passwordStrength.ts`
//! (the browser generator and the vault UI share it) — any behavior change
//! must land on BOTH sides in the same commit, and the shared test vectors in
//! [`tests`] must be mirrored in `src/utils/__tests__/passwordStrength.rust-port.test.ts`
//! (same passwords, same expected scores). The cross-language pin is the
//! regression fuse against the two UIs drifting apart.

use std::collections::HashSet;

/// The exact common-password list from passwordStrength.ts (lowercase).
const COMMON_PASSWORDS: [&str; 31] = [
    "password",
    "123456",
    "12345678",
    "qwerty",
    "abc123",
    "monkey",
    "master",
    "dragon",
    "111111",
    "baseball",
    "iloveyou",
    "trustno1",
    "sunshine",
    "princess",
    "football",
    "shadow",
    "superman",
    "michael",
    "letmein",
    "password1",
    "123456789",
    "1234567890",
    "admin",
    "welcome",
    "hello",
    "000000",
    "charlie",
    "donald",
    "qwerty123",
    "login",
    "passw0rd",
];

/// Sliding-window sources for the sequential penalty. The TS code slides a
/// 4-char window across each pattern and subtracts 10 per window found — the
/// windows overlap, so "1234567890" hits 8 windows, not 1.
const SEQUENTIAL_PATTERNS: [&str; 4] = [
    "abcdefghijklmnopqrstuvwxyz",
    "zyxwvutsrqponmlkjihgfedcba",
    "01234567890",
    "09876543210",
];

/// Score a password on the frontend's 0-100 heuristic scale.
///
/// Weights: length ≤ 30, character variety ≤ 30, unique-ratio entropy ≤ 15,
/// penalties for common passwords / 3+ repeated runs / sequential windows /
/// single character class. Floating-point math mirrors the TS implementation
/// exactly, including evaluation order (the common-password zeroing happens
/// BEFORE the penalties, which can push the score negative — clamped to 0).
pub fn score_password(password: &str) -> u32 {
    if password.is_empty() {
        return 0;
    }
    let mut score = 0.0f64;

    // Length scoring (up to 30 points). JS `.length` counts UTF-16 code
    // units, so astral-plane characters cost 2 there but 1 per `chars()` —
    // mirrored via encode_utf16 to keep both ends identical.
    let length_units = password.encode_utf16().count();
    score += (length_units as f64 * 2.5).min(30.0);

    // Character variety (up to 30 points). JS regexes are ASCII-only without
    // the unicode flag: /[a-z]/, /[A-Z]/, /\d/, /[^a-zA-Z\d]/.
    let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
    let has_numbers = password.chars().any(|c| c.is_ascii_digit());
    let has_symbols = password.chars().any(|c| !c.is_ascii_alphanumeric());
    let variety = [has_lower, has_upper, has_numbers, has_symbols]
        .iter()
        .filter(|present| **present)
        .count();
    score += variety as f64 * 7.5;

    // Entropy bonus for mixed character types (up to 15 points). JS
    // `new Set(password).size` iterates by CODE POINTS, not UTF-16 units.
    if length_units >= 8 {
        let unique_chars = password.chars().collect::<HashSet<char>>().len();
        score += ((unique_chars as f64 / length_units as f64) * 15.0).min(15.0);
    }

    // Penalties — order matters and is load-bearing.
    // Common password: exact lowercase match zeroes the accumulated score.
    if COMMON_PASSWORDS.contains(&password.to_lowercase().as_str()) {
        score = 0.0;
    }

    // Repeated characters: 10 per non-overlapping 3+ run.
    score -= count_repeated_runs(password) as f64 * 10.0;

    // Sequential characters: 10 per matching 4-char sliding window.
    let lower = password.to_lowercase();
    for pattern in SEQUENTIAL_PATTERNS {
        for start in 0..=(pattern.len() - 4) {
            if lower.contains(&pattern[start..start + 4]) {
                score -= 10.0;
            }
        }
    }

    // Only one character type
    if variety == 1 {
        score -= 15.0;
    }

    // Clamp. Both languages round halves "up" for non-negative values; a
    // negative score clamps to 0 either way.
    let rounded = score.round();
    if rounded < 0.0 {
        return 0;
    }
    (rounded.min(100.0)) as u32
}

/// JS `password.match(/(.)\1{2,}/g)` — count of non-overlapping greedy runs
/// of 3+ identical characters. Without the /u flag the regex operates on
/// UTF-16 code units and `.` never matches line terminators, so both details
/// are mirrored here (an astral-plane character is TWO alternating units and
/// can therefore never form a run — same as the TS regex sees it).
fn count_repeated_runs(password: &str) -> usize {
    // Line terminators are the only units JS `.` refuses to match.
    const LINE_TERMINATORS: [u16; 4] = [0x0A, 0x0D, 0x2028, 0x2029];
    let units: Vec<u16> = password.encode_utf16().collect();
    let mut count = 0;
    let mut index = 0;
    while index < units.len() {
        let unit = units[index];
        let mut run = 1;
        while index + run < units.len() && units[index + run] == unit {
            run += 1;
        }
        if run >= 3 && !LINE_TERMINATORS.contains(&unit) {
            count += 1;
        }
        index += run;
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shared cross-language vectors (WP1): every entry MUST produce the same
    /// score from passwordStrength.ts — mirrored 1:1 in
    /// `src/utils/__tests__/passwordStrength.rust-port.test.ts`. If you change
    /// the heuristic, change both sides and both tables in one commit.
    const SHARED_VECTORS: [(&str, u32); 18] = [
        ("", 0),
        ("password", 0),
        ("123456", 0),
        ("qwerty", 0),
        ("abc", 0),
        ("abcdefgh", 0),
        ("monkey", 0),
        ("correcthorsebatterystaple", 30),
        ("Tr0ub4dor&3", 71),
        ("aaaaaaaa", 4),
        ("D7g!kLm9@pQ2", 75),
        ("P@ssw0rd123", 71),
        ("Abcdefgh1!", 20),
        ("hello world", 53),
        ("AAAbbb123!@", 47),
        // 75 is the heuristic's ceiling (30 length + 30 variety + 15 entropy).
        ("kX9$mP2!vL5#nQ8@wR4&jF7^", 75),
        ("一二三四五六七八九十", 33),
        // Astral-plane: 8 UTF-16 units but 4 code points — the JS regex/Set
        // asymmetry lives in the UTF-16 run counter and Set-based uniqueness.
        ("😀😀😀😀", 14),
    ];

    #[test]
    fn shared_vectors_match_the_frontend_scorer() {
        for (password, expected) in SHARED_VECTORS {
            assert_eq!(
                score_password(password),
                expected,
                "score drifted from the frontend for {password:?}"
            );
        }
    }

    #[test]
    fn score_is_always_within_0_100() {
        let long_x = "x".repeat(100);
        let samples = [
            "",
            "a",
            "password",
            long_x.as_str(),
            "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
            "一二三四五六七八九十",
            "\u{1F600}\u{1F600}\u{1F600}\u{1F600}", // astral: 8 UTF-16 units, 4 code points
            "\n\n\n",
        ];
        for password in samples {
            let score = score_password(password);
            assert!(score <= 100, "{password:?} scored {score}");
        }
    }

    #[test]
    fn weak_threshold_buckets_like_the_frontend_labels() {
        // The dashboard's weak cut-off is score <= 40 ("Very Weak"/"Weak" in
        // passwordStrength.ts's label ladder).
        assert!(score_password("Tr0ub4dor&3") > 40);
        assert!(score_password("aaaaaaaa") <= 40);
        assert!(score_password("password") <= 40);
    }
}
