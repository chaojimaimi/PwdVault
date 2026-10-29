import { describe, expect, it } from 'vitest';
import {
  KEYBOARD_WALK_PATTERNS,
  getPasswordStrength,
} from '../passwordStrength';
import {
  CORE_WORDS,
  WEAK_PASSWORDS,
  coreWordFormulaHit,
  corpusExactHit,
  corpusNormalizedHit,
} from '../weakCorpus';
import { securityScoreLabel } from '../../types';

/**
 * v1.7.0 WP2 weak-classification vectors (fix_impl_plan_v1.7.0.md Appendix
 * B, frozen after the WP1 zxcvbn 3.1.1 measurements). The display layer no
 * longer shares scores with the Rust dashboard — the cross-language contract
 * is weak-CLASSIFICATION parity — so this table pins classification, not
 * meter labels: the must-weak set has to land at score ≤ 40 (the original
 * complaint was Test@12#$/Test@1qaz/Admin@123 scoring 66-68 = "Strong"),
 * while the sentinels must trip NONE of the new penalties (the legacy
 * heuristic's own label for e.g. "correcthorsebatterystaple" stays out of
 * scope by design).
 */

/** Distinct keyboard-walk windows present in the raw lowercase password. */
const walkHits = (password: string): string[] =>
  KEYBOARD_WALK_PATTERNS.filter((pattern) =>
    password.toLowerCase().includes(pattern),
  );

/** [password, expected mechanism — kept aligned with corpus.rs's notes]. */
const MUST_WEAK: Array<[string, string]> = [
  ['password1!', 'core-word formula (raw form)'],
  ['admin123', 'corpus exact + core-word formula'],
  ['Admin@123', 'core-word formula (raw form)'],
  ['Test@12#$', 'core-word formula (raw form)'],
  ['Test@1qaz', 'keyboard walk: qaz + 1qaz, 2 hits x -15 (68 - 30 = 38)'],
  ['P@ssw0rd123', 'corpus exact (famous-forms anchor)'],
  ['1qaz2wsx', 'corpus exact + keyboard walk'],
  ['woaini520', 'corpus exact (Chinese supplement)'],
  ['qq123456', 'corpus exact'],
  ['a123456', 'corpus exact'],
  ['sunshine123', 'core-word formula'],
  ['qwerty!@#', 'core-word formula'],
];

describe('weak-password classification vectors (v1.7.0 Appendix B)', () => {
  it.each(MUST_WEAK)('%s lands weak via %s', (password) => {
    expect(getPasswordStrength(password).score).toBeLessThanOrEqual(40);
  });

  it('clamps clean corpus hits to the Very Weak band (10)', () => {
    // Exact / normalized / formula hits all funnel into the same clamp; only
    // entries without further penalties (walk/sequential/repeat) stay at 10.
    for (const password of [
      'password1!',
      'admin123',
      'Admin@123',
      'Test@12#$',
      'P@ssw0rd123',
      'woaini520',
      'sunshine123',
    ]) {
      expect(getPasswordStrength(password).score).toBe(10);
    }
    // "qwerty!@#" is ALSO a keyboard walk (qwer/wert/erty) — its penalties
    // stack below the clamp, which is fine: the contract pins ≤ 40.
    expect(getPasswordStrength('qwerty!@#').score).toBeLessThanOrEqual(10);
  });

  it('Test@1qaz misses the corpus and rides the walk penalty to 38', () => {
    // Mechanism pin: the walk is load-bearing here, so the corpus checks
    // MUST stay silent (a future corpus edit adding "test@1qaz" would hide
    // the walk arithmetic this vector freezes).
    expect(corpusExactHit('Test@1qaz')).toBe(false);
    expect(corpusNormalizedHit('Test@1qaz')).toBe(false);
    expect(coreWordFormulaHit('Test@1qaz')).toBe(false);
    expect(walkHits('Test@1qaz')).toEqual(['qaz', '1qaz']);
    expect(getPasswordStrength('Test@1qaz').score).toBe(38);
  });

  it('1qaz2wsx stacks the corpus clamp with four walk hits', () => {
    expect(corpusExactHit('1qaz2wsx')).toBe(true);
    expect(walkHits('1qaz2wsx')).toEqual(['qaz', 'wsx', '1qaz', '2wsx']);
    expect(getPasswordStrength('1qaz2wsx').score).toBeLessThanOrEqual(40);
  });

  it('P@ssw0rd123 hits the famous-forms exact anchor', () => {
    // Normalization cannot reduce this form: 3→e welds the trailing digits
    // into "password12e" (corpus.rs pins the same), so the corpus carries
    // "p@ssw0rd123" as an exact anchor — exact matching lowercases first.
    expect(corpusExactHit('P@ssw0rd123')).toBe(true);
    expect(corpusNormalizedHit('P@ssw0rd123')).toBe(false);
    expect(coreWordFormulaHit('P@ssw0rd123')).toBe(false);
    expect(getPasswordStrength('P@ssw0rd123').score).toBe(10);
  });

  it('P@ssw0rd reduces to "password" through normalization', () => {
    expect(corpusExactHit('P@ssw0rd')).toBe(false);
    expect(corpusNormalizedHit('P@ssw0rd')).toBe(true);
    expect(coreWordFormulaHit('P@ssw0rd')).toBe(true);
    expect(getPasswordStrength('P@ssw0rd').score).toBe(10);
  });

  it('supplemented corpus entries hit exactly', () => {
    expect(corpusExactHit('abc123456')).toBe(true);
    expect(corpusExactHit('woaini5211314')).toBe(true);
    // The sequential-digit penalty can sink a clamped hit below 10 — still
    // deep inside the weak band, which is all the contract pins.
    expect(getPasswordStrength('abc123456').score).toBeLessThanOrEqual(10);
    expect(getPasswordStrength('woaini5211314').score).toBe(10);
  });
});

/** Appendix B false-positive sentinels — none may trip a new penalty. */
const SENTINELS = [
  'kX9$mP2!vL5#nQ8@wR4&jF7^',
  'correcthorsebatterystaple',
  'D7g!kLm9@pQ2',
  'latest#Rocket9',
  '7hE-qu1ck-b0wnes',
];

describe('false-positive sentinels (Appendix B)', () => {
  it.each(SENTINELS)('%s trips none of the new penalties', (password) => {
    expect(corpusExactHit(password)).toBe(false);
    expect(corpusNormalizedHit(password)).toBe(false);
    expect(coreWordFormulaHit(password)).toBe(false);
    expect(walkHits(password)).toEqual([]);
  });

  it('sentinels are absent from the corpus in lowercase AND normalized form', () => {
    // Appendix A build-time check, mirrored from corpus.rs: a corpus edit
    // that lands any of these (either form) would flip the pins above.
    for (const [sentinel, normalized] of [
      ['kx9$mp2!vl5#nq8@wr4&jf7^', 'kx9smp2!vl5s#nq8awra&jft^'],
      ['correcthorsebatterystaple', 'correcthorsebatterystaple'],
      ['d7g!klm9@pq2', 'dtg!klm9apq2'],
      ['latest#rocket9', 'latest#rocket9'],
      ['7he-qu1ck-b0wnes', 'the-qu1ck-bownes'],
    ] as Array<[string, string]>) {
      expect(WEAK_PASSWORDS.has(sentinel)).toBe(false);
      expect(WEAK_PASSWORDS.has(normalized)).toBe(false);
    }
  });
});

describe('corpus layer boundary cases (mirrors corpus.rs unit tests)', () => {
  it('empty string hits nothing', () => {
    expect(corpusExactHit('')).toBe(false);
    expect(corpusNormalizedHit('')).toBe(false);
    expect(coreWordFormulaHit('')).toBe(false);
  });

  it('pure digits hit nothing', () => {
    expect(coreWordFormulaHit('1234567890')).toBe(false);
  });

  it('non-ASCII input hits nothing', () => {
    expect(corpusExactHit('一二三四五六七八九十')).toBe(false);
    expect(corpusNormalizedHit('一二三四五六七八九十')).toBe(false);
    expect(coreWordFormulaHit('一二三四五六七八九十')).toBe(false);
  });

  it('boundary rules reject prose and embedded words', () => {
    expect(coreWordFormulaHit('xtests123')).toBe(false); // letter left of "test"
    expect(coreWordFormulaHit('testabc123')).toBe(false); // letters after
    expect(coreWordFormulaHit('test')).toBe(false); // pure-letter gate
  });

  it('dual-form search: raw and normalized forms are both examined', () => {
    // Raw-form hit: "admin" at the string start with a digit/symbol tail.
    expect(coreWordFormulaHit('Admin@123')).toBe(true);
    // Normalized-form hit: raw "pass" is prose-blocked ("@ssw0rd" still has
    // letters), the normalized "password" supplies the hit.
    expect(coreWordFormulaHit('P@ssw0rd')).toBe(true);
  });

  it('corpus parses to 9952 entries; excluded words never join CORE_WORDS', () => {
    expect(WEAK_PASSWORDS.size).toBe(9952);
    expect(WEAK_PASSWORDS.has('a123456')).toBe(true);
    expect(WEAK_PASSWORDS.has('1qaz2wsx')).toBe(true);
    for (const excluded of [
      'latest',
      'rocket',
      'quick',
      'brown',
      'correct',
      'horse',
      'battery',
      'staple',
      'troubador',
    ]) {
      expect(CORE_WORDS.has(excluded)).toBe(false);
    }
  });
});

describe('securityScoreLabel (wire 0-4 → dashboard label)', () => {
  it('mirrors the Rust classify_password mapping', () => {
    expect(securityScoreLabel(0)).toBe('Very Weak');
    expect(securityScoreLabel(1)).toBe('Weak');
    expect(securityScoreLabel(2)).toBe('Weak');
    expect(securityScoreLabel(3)).toBe('Fair');
    expect(securityScoreLabel(4)).toBe('Strong');
  });

  it('degrades out-of-band scores to Weak (the list only holds weak findings)', () => {
    expect(securityScoreLabel(12)).toBe('Weak');
  });
});
