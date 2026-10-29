//! Password strength classification (v1.7.0 WP1) — the dashboard's authority.
//!
//! v1.5.0 shipped a character-statistics heuristic port (`score_password`);
//! real passwords like `Test@12#$` scored 66-100 on its 0-100 scale and the
//! ≤40 weak line missed every one (no dictionary/pattern/keyboard models).
//! v1.7.0 replaces it with a two-layer verdict (fix_impl_plan_v1.7.0.md §2):
//!
//! ```text
//! weak  =  empty password ∪ corpus layer hit ∪ zxcvbn score ≤ 2
//! Fair  =  zxcvbn score = 3        Strong = zxcvbn score = 4
//! ```
//!
//! - The corpus layer ([`crate::corpus`]) is the same algorithm the frontend
//!   display layer ports; it independently forces Weak (double insurance,
//!   and the workaround for zxcvbn's missing custom-dictionary API).
//! - zxcvbn is exact-pinned (`"=3.1.1"`): the classification freeze table
//!   (Appendix B) is scored against that version, and a minor bump can
//!   silently re-grade the pins.
//! - Scores are NOT aligned with the frontend meter — only the weak
//!   classification is (Appendix B). The cross-language per-score pin
//!   (`passwordStrength.rust-port.test.ts`) retired together with
//!   `score_password`; the dashboard may legitimately disagree with the
//!   meter on individual passwords, and that is the documented design.
//!
//! API note (verified against the 3.1.1 source): `zxcvbn()` returns
//! `Entropy` directly — there is no `Err` path to fail safe on. It also
//! short-circuits the empty string to `Score::Zero` internally; the explicit
//! empty branch below keeps that contract visible and independent of the
//! crate, and the wildcard match arm keeps any future zxcvbn variant
//! fail-safe on the Weak side.

use zxcvbn::Score;

/// Dashboard strength verdict (v1.7.0 semantics). Not a 0-100 score —
/// the weak/fair/strong trichotomy the dashboard acts on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordVerdict {
    /// Weak: empty, a corpus-layer hit, or zxcvbn score ≤ 2.
    Weak,
    /// Fair: zxcvbn score = 3, no corpus hit.
    Fair,
    /// Strong: zxcvbn score = 4, no corpus hit.
    Strong,
}

/// Classify a password for the security dashboard.
///
/// Layer order matters: the corpus check runs BEFORE zxcvbn so a corpus hit
/// forces Weak even when zxcvbn grades the password Fair/Strong (the
/// dashboard then caps the wire score — see security_report.rs).
pub fn classify_password(password: &str) -> PasswordVerdict {
    // Empty is Weak by long-standing dashboard behavior (empty password
    // fields are legal on historical backup-restored rows and must land on
    // the weak list — security_report.rs tests pin this).
    if password.is_empty() {
        return PasswordVerdict::Weak;
    }
    if crate::corpus::corpus_hit(password) {
        return PasswordVerdict::Weak;
    }
    match zxcvbn::zxcvbn(password, &[]).score() {
        Score::Zero | Score::One | Score::Two => PasswordVerdict::Weak,
        Score::Three => PasswordVerdict::Fair,
        Score::Four => PasswordVerdict::Strong,
        // Fail-safe wildcard (Score is #[non_exhaustive]): any future
        // zxcvbn variant degrades to Weak, never to a false Strong.
        _ => PasswordVerdict::Weak,
    }
}

/// Raw zxcvbn 0-4 grade (empty string → 0). Wire-payload number for the
/// dashboard; weak VERDICTS must come from [`classify_password`], which also
/// folds in the corpus layer.
pub fn zxcvbn_score(password: &str) -> u8 {
    zxcvbn::zxcvbn(password, &[]).score() as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Freeze table, must-weak half (fix_impl_plan_v1.7.0.md Appendix B;
    /// zxcvbn 3.1.1 actual scores recorded by the WP1 freeze pretest,
    /// 2026-10-29 — see the completion report). Every entry classifies Weak.
    /// The corpus layer covers eleven of the twelve (post-anchor sync: the
    /// famous-form entry "p@ssw0rd123" in weak_passwords.txt carries that
    /// vector by EXACT hit, though its normalization still misses — the
    /// pinned 3→e mapping welds it into "password12e", plan defect recorded
    /// in the report); only "Test@1qaz" is carried by zxcvbn alone (the
    /// right-boundary rule lets the embedded "test" pass — R2 P1).
    #[test]
    fn freeze_table_must_weak_vectors_classify_weak() {
        for password in [
            ("password1!", 1u8),
            ("admin123", 1),
            ("Admin@123", 2),
            ("Test@12#$", 2),
            ("Test@1qaz", 2),
            ("P@ssw0rd123", 1),
            ("1qaz2wsx", 0),
            ("woaini520", 2),
            ("qq123456", 1),
            ("a123456", 0),
            ("sunshine123", 1),
            ("qwerty!@#", 1),
        ] {
            assert_eq!(
                classify_password(password.0),
                PasswordVerdict::Weak,
                "{:?} (zxcvbn {})",
                password.0,
                password.1
            );
        }
    }

    /// Freeze table, sentinel half: the false-positive defense. All five
    /// scored 4 under zxcvbn 3.1.1 (no replacement needed) and miss every
    /// corpus check (corpus.rs pins the absence per-form).
    #[test]
    fn freeze_table_sentinels_do_not_classify_weak() {
        for password in [
            "kX9$mP2!vL5#nQ8@wR4&jF7^",
            "correcthorsebatterystaple",
            "D7g!kLm9@pQ2",
            "latest#Rocket9",
            "7hE-qu1ck-b0wnes",
        ] {
            assert_ne!(
                classify_password(password),
                PasswordVerdict::Weak,
                "{password:?} falsely weak"
            );
        }
    }

    /// zxcvbn ≤ 2 boundary vectors, actual scores 0/0/1 from the pretest.
    /// "1234567890" is also an exact corpus entry — either path suffices.
    #[test]
    fn zxcvbn_weak_boundary_vectors_classify_weak() {
        for password in ["abcdefgh", "1234567890", "ABCDEFGH!"] {
            assert_eq!(classify_password(password), PasswordVerdict::Weak);
            assert!(zxcvbn_score(password) <= 2, "{password:?}");
        }
    }

    /// The corpus layer overrules zxcvbn: an exact corpus entry graded Fair
    /// (3) and a core-word-formula hit graded Strong (4) both classify Weak.
    #[test]
    fn corpus_hits_force_weak_even_at_high_zxcvbn_scores() {
        assert_eq!(zxcvbn_score("woaini5211314"), 3);
        assert_eq!(classify_password("woaini5211314"), PasswordVerdict::Weak);
        assert_eq!(zxcvbn_score("iloveyou84920173@!"), 4);
        assert_eq!(
            classify_password("iloveyou84920173@!"),
            PasswordVerdict::Weak
        );
    }

    /// Empty passwords are Weak by long-standing dashboard behavior (the
    /// aggregate_report tests pin the wire shape).
    #[test]
    fn empty_password_classifies_weak() {
        assert_eq!(classify_password(""), PasswordVerdict::Weak);
        assert_eq!(zxcvbn_score(""), 0);
    }

    /// Grade ladder sanity: Fair (3) and Strong (4) are reachable and
    /// distinct from Weak for corpus-clean passwords.
    #[test]
    fn fair_and_strong_grades_are_reachable() {
        assert_eq!(classify_password("hello world"), PasswordVerdict::Fair);
        assert_eq!(zxcvbn_score("hello world"), 3);
        assert_eq!(
            classify_password("correcthorsebatterystaple"),
            PasswordVerdict::Strong
        );
        assert_eq!(zxcvbn_score("correcthorsebatterystaple"), 4);
    }
}
