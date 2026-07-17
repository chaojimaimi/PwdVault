import { getPasswordStrength } from '../utils/passwordStrength';

interface StrengthMeterProps {
  password: string;
}

export function StrengthMeter({ password }: StrengthMeterProps) {
  if (!password) return null;

  const strength = getPasswordStrength(password);
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
