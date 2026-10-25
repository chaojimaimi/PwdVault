import { render } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { StrengthMeter } from './StrengthMeter';

const mockedStrength = vi.hoisted(() => ({ score: 20, label: 'Weak' }));

vi.mock('../utils/passwordStrength', () => ({
  // v1.4.0: the meter routes through the mode-aware entry now — the mock
  // covers both exports and ignores the extra arguments.
  getPasswordStrength: () => mockedStrength,
  getGeneratorStrength: (_mode: string, _value: string, _params: unknown) =>
    mockedStrength,
}));

describe('StrengthMeter', () => {
  it.each([20, 50, 100])('renders a %s%% fill with accessible meter semantics', (score) => {
    mockedStrength.score = score;
    const { container, unmount } = render(<StrengthMeter password="test" />);
    const meter = container.querySelector('[role="meter"]');
    const track = container.querySelector<HTMLProgressElement>('.strength-track');
    expect(meter).toHaveAttribute('aria-valuenow', String(score));
    expect(track?.value).toBe(score);
    expect(track?.max).toBe(100);
    unmount();
  });
});
