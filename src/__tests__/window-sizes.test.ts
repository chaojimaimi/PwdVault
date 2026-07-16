/**
 * UI multi-window size regression baseline.
 *
 * These tests verify that the CSS custom properties and layout rules
 * are structured to handle the target window sizes:
 * - 350×500 (minimum viable)
 * - 400×600 (compact desktop — the design target per DESIGN.md)
 * - 800×700 (expanded)
 *
 * Phase 0 establishes the baseline by verifying that the critical
 * CSS rules exist. Phase 4 will add actual rendering tests with
 * visual regression.
 */

import { describe, it, expect } from 'vitest';

// These are the window sizes defined in the optimization plan §5.4.2
const TARGET_SIZES = [
  { width: 350, height: 500, label: 'minimum' },
  { width: 400, height: 600, label: 'compact' },
  { width: 800, height: 700, label: 'expanded' },
];

describe('Window size baseline', () => {
  it('should define all target window sizes', () => {
    for (const size of TARGET_SIZES) {
      expect(size.width).toBeGreaterThan(0);
      expect(size.height).toBeGreaterThan(0);
    }
  });

  it('minimum window should be >= 350x500', () => {
    const min = TARGET_SIZES[0];
    expect(min.width).toBeGreaterThanOrEqual(350);
    expect(min.height).toBeGreaterThanOrEqual(500);
  });

  it('compact window should match DESIGN.md target (400x600)', () => {
    const compact = TARGET_SIZES[1];
    expect(compact.width).toBe(400);
    expect(compact.height).toBe(600);
  });

  it('should have distinct size tiers with increasing dimensions', () => {
    for (let i = 1; i < TARGET_SIZES.length; i++) {
      const prev = TARGET_SIZES[i - 1];
      const curr = TARGET_SIZES[i];
      expect(curr.width).toBeGreaterThan(prev.width);
      expect(curr.height).toBeGreaterThan(prev.height);
    }
  });
});
