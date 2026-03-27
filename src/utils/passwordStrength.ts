const COMMON_PASSWORDS = new Set([
  'password', '123456', '12345678', 'qwerty', 'abc123', 'monkey', 'master',
  'dragon', '111111', 'baseball', 'iloveyou', 'trustno1', 'sunshine',
  'princess', 'football', 'shadow', 'superman', 'michael', 'letmein',
  'password1', '123456789', '1234567890', 'admin', 'welcome', 'hello',
  '000000', 'charlie', 'donald', 'qwerty123', 'login', 'passw0rd',
]);

const SEQUENTIAL_PATTERNS = [
  'abcdefghijklmnopqrstuvwxyz',
  'zyxwvutsrqponmlkjihgfedcba',
  '01234567890',
  '09876543210',
];

export interface PasswordStrength {
  score: number;
  label: string;
  color: string;
}

export function getPasswordStrength(password: string): PasswordStrength {
  if (!password) return { score: 0, label: '', color: 'transparent' };

  let score = 0;

  // Length scoring (up to 30 points)
  score += Math.min(30, password.length * 2.5);

  // Character variety (up to 30 points)
  const hasLower = /[a-z]/.test(password);
  const hasUpper = /[A-Z]/.test(password);
  const hasNumbers = /\d/.test(password);
  const hasSymbols = /[^a-zA-Z\d]/.test(password);

  const variety = [hasLower, hasUpper, hasNumbers, hasSymbols].filter(Boolean).length;
  score += variety * 7.5;

  // Entropy bonus for mixed character types (up to 15 points)
  if (password.length >= 8) {
    const uniqueChars = new Set(password).size;
    score += Math.min(15, (uniqueChars / password.length) * 15);
  }

  // Penalties
  // Common password
  if (COMMON_PASSWORDS.has(password.toLowerCase())) {
    score = 0;
  }

  // Repeated characters
  const repeatedChars = (password.match(/(.)\1{2,}/g) || []).length;
  score -= repeatedChars * 10;

  // Sequential characters
  const lower = password.toLowerCase();
  for (const pattern of SEQUENTIAL_PATTERNS) {
    for (let i = 0; i <= pattern.length - 4; i++) {
      if (lower.includes(pattern.substring(i, i + 4))) {
        score -= 10;
      }
    }
  }

  // Only one character type
  if (variety === 1) score -= 15;

  // Clamp
  score = Math.max(0, Math.min(100, Math.round(score)));

  // Determine label and color
  let label: string;
  let color: string;
  if (score <= 20) {
    label = 'Very Weak';
    color = '#ef4444';
  } else if (score <= 40) {
    label = 'Weak';
    color = '#f97316';
  } else if (score <= 60) {
    label = 'Fair';
    color = '#eab308';
  } else if (score <= 80) {
    label = 'Strong';
    color = '#22c55e';
  } else {
    label = 'Very Strong';
    color = '#10b981';
  }

  return { score, label, color };
}
