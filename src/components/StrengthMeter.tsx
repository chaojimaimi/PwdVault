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
        style={{
          '--strength-fill': `${strength.score}%`,
          '--strength-color': strength.color,
        } as React.CSSProperties}
      />
      <span
        className="strength-label"
        style={{ '--strength-color': strength.color } as React.CSSProperties}
      >
        {strength.label}
      </span>
    </div>
  );
}
