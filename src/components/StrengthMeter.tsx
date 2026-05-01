import { getPasswordStrength } from '../utils/passwordStrength';

interface StrengthMeterProps {
  password: string;
}

export function StrengthMeter({ password }: StrengthMeterProps) {
  if (!password) return null;

  const strength = getPasswordStrength(password);

  return (
    <div className="strength-meter">
      <div
        className="strength-bar"
        style={{ width: `${strength.score}%`, backgroundColor: strength.color }}
      />
      <span className="strength-label" style={{ color: strength.color }}>
        {strength.label}
      </span>
    </div>
  );
}
