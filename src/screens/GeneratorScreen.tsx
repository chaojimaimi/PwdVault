import { useState, useEffect } from 'react';
import { useApp } from '../context/AppContext';
import { generatePassword } from '../api/vault';
import { getPasswordStrength } from '../utils/passwordStrength';
import { copyWithTimeout } from '../utils/clipboard';
import { showToast } from '../utils/toast';
import type { PasswordGeneratorOptions } from '../types';

export function GeneratorScreen() {
  const { state, actions } = useApp();
  const [password, setPassword] = useState('');
  const [options, setOptions] = useState<PasswordGeneratorOptions>({
    length: state.settings.default_length,
    includeUppercase: state.settings.default_include_uppercase,
    includeLowercase: state.settings.default_include_lowercase,
    includeNumbers: state.settings.default_include_numbers,
    includeSymbols: state.settings.default_include_symbols,
  });
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    handleGenerate();
  }, []);

  const handleGenerate = async () => {
    try {
      const pwd = await generatePassword(options);
      setPassword(pwd);
      setCopied(false);
    } catch (error) {
      console.error('Failed to generate password:', error);
    }
  };

  const handleCopy = async () => {
    await copyWithTimeout(password);
    setCopied(true);
    showToast('Password copied (auto-clears in 30s)');
    setTimeout(() => setCopied(false), 2000);
  };

  const handleBack = () => {
    actions.navigate('vault');
  };

  const handleOptionChange = (key: keyof PasswordGeneratorOptions, value: boolean | number) => {
    setOptions({ ...options, [key]: value });
  };

  return (
    <div className="generator-screen">
      <header className="generator-header">
        <button className="btn btn-icon" onClick={handleBack}>
          <svg className="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M19 12H5M12 19l-7-7 7-7" />
          </svg>
        </button>
        <h2>Password Generator</h2>
        <div style={{ width: '40px' }} />
      </header>

      <div className="generator-content">
        <div className="password-preview">
          {password || 'Generating...'}
        </div>
        {password && (() => {
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
        })()}

        <div className="option-group">
          <div className="option-row">
            <label>Length: {options.length}</label>
          </div>
          <div className="length-control">
            <input
              type="range"
              min="8"
              max="64"
              value={options.length}
              onChange={(e) => handleOptionChange('length', parseInt(e.target.value))}
            />
          </div>
        </div>

        <div className="option-group">
          <div className="option-row">
            <label>Uppercase (A-Z)</label>
            <input
              type="checkbox"
              className="checkbox"
              checked={options.includeUppercase}
              onChange={(e) => handleOptionChange('includeUppercase', e.target.checked)}
            />
          </div>

          <div className="option-row">
            <label>Lowercase (a-z)</label>
            <input
              type="checkbox"
              className="checkbox"
              checked={options.includeLowercase}
              onChange={(e) => handleOptionChange('includeLowercase', e.target.checked)}
            />
          </div>

          <div className="option-row">
            <label>Numbers (0-9)</label>
            <input
              type="checkbox"
              className="checkbox"
              checked={options.includeNumbers}
              onChange={(e) => handleOptionChange('includeNumbers', e.target.checked)}
            />
          </div>

          <div className="option-row">
            <label>Symbols (!@#$...)</label>
            <input
              type="checkbox"
              className="checkbox"
              checked={options.includeSymbols}
              onChange={(e) => handleOptionChange('includeSymbols', e.target.checked)}
            />
          </div>
        </div>

        <button className="btn btn-secondary" onClick={handleGenerate}>
          Generate New Password
        </button>
      </div>

      <div className="generator-actions">
        <button className="btn btn-primary" onClick={handleCopy}>
          {copied ? 'Copied!' : 'Copy to Clipboard'}
        </button>
      </div>
    </div>
  );
}