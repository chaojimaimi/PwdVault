import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import indexHtml from '../../index.html?raw';

const baseCss = readFileSync('src/styles/base.css', 'utf8');
const screensCss = readFileSync('src/styles/screens.css', 'utf8');
const themesCss = readFileSync('src/styles/themes.css', 'utf8');

describe('Phase 4 static UI contracts', () => {
  it('boots offline without legacy themes, remote fonts, or inline script/style blocks', () => {
    expect(indexHtml).not.toMatch(/fonts\.googleapis|fonts\.gstatic|classic|cyber|hybrid/i);
    expect(indexHtml).not.toContain('<style');
    const scripts = Array.from(indexHtml.matchAll(/<script([^>]*)>/g), (match) => match[1]);
    expect(scripts.length).toBeGreaterThan(0);
    expect(scripts.every((attributes) => attributes.includes('type="module"') && attributes.includes('src='))).toBe(true);
  });

  it('defines the shared dynamic viewport shell and scroll region contract', () => {
    expect(baseCss).toContain('height: 100dvh');
    expect(baseCss).toContain('.screen-shell');
    expect(baseCss).toContain('.screen-scroll-region');
    expect(baseCss).toContain('min-height: 0');
    expect(screensCss).toContain('overflow-y: auto');
    expect(screensCss).toContain('@media (max-width: 370px), (max-height: 540px)');
  });

  it('defines semantic foreground tokens for every action color', () => {
    expect(themesCss).toContain('--color-on-primary');
    expect(themesCss).toContain('--color-on-danger');
    expect(themesCss).toContain('--color-on-success');
  });

  it('keeps critical foreground/background pairs at WCAG AA contrast', () => {
    const pairs = [
      ['1E3A5F', 'FFFFFF'],
      ['DC2626', 'FFFFFF'],
      ['64748B', 'F8FAFC'],
      ['14B8A6', '02110F'],
      ['F87171', '220505'],
      ['8A93A3', '020203'],
    ];
    for (const [foreground, background] of pairs) {
      expect(themesCss.toUpperCase()).toContain(`#${foreground}`);
      expect(contrastRatio(foreground, background)).toBeGreaterThanOrEqual(4.5);
    }
  });
});

function contrastRatio(foreground: string, background: string): number {
  const luminance = (hex: string) => {
    const channels = hex.match(/../g)?.map((part) => parseInt(part, 16) / 255) ?? [];
    const [red, green, blue] = channels.map((value) => (
      value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4
    ));
    return 0.2126 * red + 0.7152 * green + 0.0722 * blue;
  };
  const first = luminance(foreground);
  const second = luminance(background);
  return (Math.max(first, second) + 0.05) / (Math.min(first, second) + 0.05);
}
