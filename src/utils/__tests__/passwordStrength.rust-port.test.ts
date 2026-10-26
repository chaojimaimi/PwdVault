import { describe, it, expect } from 'vitest';
import { getPasswordStrength } from '../passwordStrength';

// WP1 (v1.5.0) shared cross-language vectors: this table MIRRORS the
// `SHARED_VECTORS` constant in
// src-tauri/crates/domain/src/strength.rs (the Rust port the security
// dashboard aggregates with). Both sides must produce the SAME score for the
// SAME password — if you change the heuristic, change both implementations
// and both tables in one commit. Vectors were captured from the TS
// implementation and asserted green against the Rust port.
const SHARED_VECTORS: Array<[string, number]> = [
  ['', 0],
  ['password', 0],
  ['123456', 0],
  ['qwerty', 0],
  ['abc', 0],
  ['abcdefgh', 0],
  ['monkey', 0],
  ['correcthorsebatterystaple', 30],
  ['Tr0ub4dor&3', 71],
  ['aaaaaaaa', 4],
  ['D7g!kLm9@pQ2', 75],
  ['P@ssw0rd123', 71],
  ['Abcdefgh1!', 20],
  ['hello world', 53],
  ['AAAbbb123!@', 47],
  // 75 is the heuristic's ceiling (30 length + 30 variety + 15 entropy).
  ['kX9$mP2!vL5#nQ8@wR4&jF7^', 75],
  ['一二三四五六七八九十', 33],
  // Astral-plane: 8 UTF-16 units but 4 code points.
  ['😀😀😀😀', 14],
];

describe('passwordStrength rust-port parity vectors', () => {
  it.each(SHARED_VECTORS)('%# scores %j identically to the Rust port', (password, expected) => {
    expect(getPasswordStrength(password).score).toBe(expected);
  });
});
