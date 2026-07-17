import { useMemo } from 'react';
import { getPasswordStrength } from '../utils/passwordStrength';

interface StrengthMeterProps {
  password: string;
}

export function StrengthMeter({ password }: StrengthMeterProps) {
  // §5.6.1: memoize the strength calculation so it only recomputes when the
  // password changes, not on every parent re-render.
  const strength = useMemo(() => password ? getPasswordStrength(password) : null, [password]);
  if (!strength) return null;

  const strengthClass = strength.label.toLowerCase().replace(/\s+/g, '-');

  return (
    <div
      className="strength-meter"
      role="meter"
      aria-label={`Password strength: ${strength.label}`}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={strength.score}
      aria-valuetext={strength.label}
    >
      <progress
        className={`strength-track strength-${strengthClass}`}
        value={strength.score}
        max={100}
        aria-hidden="true"
      />
      <span className={`strength-label strength-${strengthClass}`}>
        {strength.label}
      </span>
    </div>
  );
}
