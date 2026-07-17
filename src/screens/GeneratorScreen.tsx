import { useState, useEffect } from 'react';
import { useApp } from '../context/AppContext';
import { generatePassword } from '../api/vault';
import { copyWithTimeout } from '../utils/clipboard';
import { showToast } from '../utils/toast';
import { BackHeader } from '../components/BackHeader';
import { StrengthMeter } from '../components/StrengthMeter';
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
  const [pending, setPending] = useState(false);
  const charsetValid = options.includeUppercase || options.includeLowercase || options.includeNumbers || options.includeSymbols;

  useEffect(() => {
    handleGenerate();
  }, []);

  const handleGenerate = async () => {
    if (!charsetValid || pending) return;
    setPending(true);
    try {
      const pwd = await generatePassword(options);
      setPassword(pwd);
      setCopied(false);
    } catch (error) {
      showToast(error instanceof Error ? error.message : 'Failed to generate password');
    } finally {
      setPending(false);
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
    <div className="generator-screen screen-shell">
      <BackHeader title="Password Generator" onBack={handleBack} />

      <div className="generator-content screen-scroll-region">
        <div className="password-preview">
          {password || 'Generating...'}
        </div>
        <StrengthMeter password={password} />

        <div className="option-group">
          <div className="option-row">
            <label htmlFor="gen-length">Length: {options.length}</label>
          </div>
          <div className="length-control">
            <input
              id="gen-length"
              type="range"
              min="8"
              max="64"
              value={options.length}
              aria-label="Password length"
              aria-valuemin={8}
              aria-valuemax={64}
              aria-valuenow={options.length}
              onChange={(e) => handleOptionChange('length', parseInt(e.target.value))}
            />
          </div>
        </div>

        <div className="option-group">
          <div className="option-row">
            <label htmlFor="gen-upper">Uppercase (A-Z)</label>
            <input
              id="gen-upper"
              type="checkbox"
              className="checkbox"
              checked={options.includeUppercase}
              onChange={(e) => handleOptionChange('includeUppercase', e.target.checked)}
            />
          </div>

          <div className="option-row">
            <label htmlFor="gen-lower">Lowercase (a-z)</label>
            <input
              id="gen-lower"
              type="checkbox"
              className="checkbox"
              checked={options.includeLowercase}
              onChange={(e) => handleOptionChange('includeLowercase', e.target.checked)}
            />
          </div>

          <div className="option-row">
            <label htmlFor="gen-numbers">Numbers (0-9)</label>
            <input
              id="gen-numbers"
              type="checkbox"
              className="checkbox"
              checked={options.includeNumbers}
              onChange={(e) => handleOptionChange('includeNumbers', e.target.checked)}
            />
          </div>

          <div className="option-row">
            <label htmlFor="gen-symbols">Symbols (!@#$...)</label>
            <input
              id="gen-symbols"
              type="checkbox"
              className="checkbox"
              checked={options.includeSymbols}
              onChange={(e) => handleOptionChange('includeSymbols', e.target.checked)}
            />
          </div>
        </div>

        {!charsetValid && <p className="error-message" role="alert">Select at least one character set.</p>}

        <button className="btn btn-secondary" onClick={handleGenerate} disabled={!charsetValid || pending}>
          {pending ? 'Generating…' : 'Generate New Password'}
        </button>
      </div>

      <div className="generator-actions">
        <button className="btn btn-primary" onClick={handleCopy} disabled={!password}>
          {copied ? 'Copied!' : 'Copy to Clipboard'}
        </button>
      </div>
    </div>
  );
}
