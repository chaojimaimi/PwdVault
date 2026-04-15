# Design System — PwdVault

## Product Context
- **What this is:** Local-first, encrypted password manager built with Tauri v2 + React
- **Who it's for:** Privacy-conscious desktop users who want control over their credentials
- **Space/industry:** Security tools (1Password, Bitwarden, KeePassXC)
- **Project type:** Desktop app (compact 400×600 window) with browser extension

## Aesthetic Direction
- **Direction:** Industrial Refined (default), with CyberForge and Hybrid alternatives
- **Decoration level:** Minimal — typography and color do all the work
- **Mood:** Precise, trustworthy, purpose-built. Not decorative, not generic.
- **Reference products:** 1Password (warmth), KeePassXC (utilitarian honesty)

## Theme System

PwdVault supports three visual themes, switchable via Settings.

### Theme 1: Classic (Default) — Industrial Refined

Warm, reliable precision tool aesthetic.

| Token | Value | Usage |
|-------|-------|-------|
| `--color-primary` | `#0EA5E9` | Buttons, links, accents |
| `--color-primary-hover` | `#0284C7` | Hover states |
| `--color-primary-dim` | `rgba(14, 165, 233, 0.15)` | Light backgrounds, badges |
| `--color-primary-border` | `rgba(14, 165, 233, 0.3)` | Focused borders |
| `--color-bg` | `#0F0F14` | Main background (near-black, slight purple) |
| `--color-surface` | `#16161E` | Cards, panels |
| `--color-input` | `#1C1C26` | Input fields, interactive areas |
| `--color-text` | `#E8E8ED` | Primary text |
| `--color-text-secondary` | `#8888A0` | Labels, descriptions |
| `--color-text-muted` | `#555570` | Placeholders, timestamps |
| `--color-border` | `#2A2A3A` | Dividers, card borders |
| `--color-border-light` | `#333346` | Hover borders |
| `--color-success` | `#10B981` | Success states |
| `--color-danger` | `#EF4444` | Error, delete, danger |
| `--color-danger-hover` | `#DC2626` | Danger hover |
| `--color-warning` | `#F59E0B` | Warnings |
| `--color-accent` | `#0EA5E9` | Same as primary (single-accent) |
| `--color-accent-dim` | `rgba(14, 165, 233, 0.15)` | Accent light bg |

- **Font body:** Plus Jakarta Sans
- **Font mono:** JetBrains Mono
- **Border radius:** sm=6px, md=8px, lg=12px
- **Glow:** None
- **Button case:** Normal (Create Entry)
- **Icon style:** Solid fill on primary color background

### Theme 2: Cyber — CyberForge

Cyberpunk digital arsenal aesthetic. For users who want a tech-forward feel.

| Token | Value | Usage |
|-------|-------|-------|
| `--color-primary` | `#00F0FF` | Neon cyan |
| `--color-primary-hover` | `#00C8D6` | Hover |
| `--color-primary-dim` | `rgba(0, 240, 255, 0.08)` | Light bg |
| `--color-primary-border` | `rgba(0, 240, 255, 0.3)` | Borders |
| `--color-accent` | `#FF0080` | Hot magenta (secondary accent) |
| `--color-accent-dim` | `rgba(255, 0, 128, 0.1)` | Accent light bg |
| `--color-bg` | `#050508` | Void black |
| `--color-surface` | `#0A0A10` | Surface |
| `--color-input` | `#0E0E16` | Input fields |
| `--color-text` | `#E0E0F0` | Primary text |
| `--color-text-secondary` | `#6E6E8A` | Secondary text |
| `--color-text-muted` | `#3E3E58` | Muted text |
| `--color-border` | `rgba(255, 255, 255, 0.06)` | Borders |
| `--color-border-light` | `rgba(255, 255, 255, 0.1)` | Hover borders |
| `--color-success` | `#00FF88` | Neon green |
| `--color-danger` | `#FF3366` | Hot red |
| `--color-warning` | `#FFB800` | Amber |

- **Font body:** Space Grotesk
- **Font mono:** Space Mono
- **Border radius:** sm=4px, md=6px, lg=8px
- **Glow:** Yes — `box-shadow: 0 0 20px rgba(0, 240, 255, 0.15)` on interactive elements
- **Background:** Grid pattern overlay at 2% opacity
- **Button case:** UPPERCASE
- **Icon style:** Border + glow outline, hollow

### Theme 3: Hybrid

Warm-tech fusion. Cyan + Rose dual tone with subtle glow.

| Token | Value | Usage |
|-------|-------|-------|
| `--color-primary` | `#06B6D4` | Cyan |
| `--color-primary-hover` | `#0891B2` | Hover |
| `--color-primary-dim` | `rgba(6, 182, 212, 0.10)` | Light bg |
| `--color-primary-border` | `rgba(6, 182, 212, 0.25)` | Borders |
| `--color-accent` | `#F472B6` | Rose (secondary accent) |
| `--color-accent-dim` | `rgba(244, 114, 182, 0.10)` | Accent light bg |
| `--color-bg` | `#0B0B12` | Background |
| `--color-surface` | `#111119` | Surface |
| `--color-input` | `#18181F` | Input fields |
| `--color-text` | `#E4E4F0` | Primary text |
| `--color-text-secondary` | `#7C7C96` | Secondary text |
| `--color-text-muted` | `#4A4A64` | Muted text |
| `--color-border` | `rgba(255, 255, 255, 0.05)` | Borders |
| `--color-border-light` | `rgba(255, 255, 255, 0.08)` | Hover borders |
| `--color-success` | `#34D399` | Green |
| `--color-danger` | `#F87171` | Red |
| `--color-warning` | `#FBBF24` | Amber |

- **Font body:** Plus Jakarta Sans
- **Font mono:** JetBrains Mono (password fields display in primary color)
- **Border radius:** sm=6px, md=8px, lg=10px
- **Glow:** Subtle — `box-shadow: 0 0 16px rgba(6, 182, 212, 0.12)` on hover only
- **Background:** Radial gradient — cyan glow top-left + rose glow bottom-right at 2-3% opacity
- **Button case:** Normal
- **Icon style:** Border + subtle glow, semi-transparent

## Typography

### Classic & Hybrid
| Role | Font | Fallback |
|------|------|----------|
| Body | Plus Jakarta Sans | system-ui, sans-serif |
| Data/Passwords | JetBrains Mono | ui-monospace, monospace |

### Cyber
| Role | Font | Fallback |
|------|------|----------|
| Body | Space Grotesk | system-ui, sans-serif |
| Data/Passwords | Space Mono | ui-monospace, monospace |

### Type Scale (all themes)
| Level | Size | Usage |
|-------|------|-------|
| H1 | 1.5rem (24px) | Page titles |
| H2 | 1.125rem (18px) | Card titles |
| Body | 0.875rem (14px) | Body text, inputs |
| Label | 0.75rem (12px) | Labels, tags |
| Micro | 0.6875rem (11px) | Timestamps, metadata |
| Mono | 0.8125rem (13px) | Passwords, URLs |

### Loading
- Plus Jakarta Sans: Google Fonts CDN
- JetBrains Mono: Google Fonts CDN
- Space Grotesk: Google Fonts CDN
- Space Mono: Google Fonts CDN
- Only load fonts needed by the active theme

## Spacing
- **Base unit:** 4px
- **Density:** Compact (optimized for 400×600 window)

| Name | Value | Usage |
|------|-------|-------|
| xs | 4px | Icon-text gap |
| sm | 8px | Button padding |
| md | 12px | Form group spacing |
| lg | 16px | Card padding |
| xl | 24px | Section spacing |
| 2xl | 32px | Page margin |

## Layout
- **Approach:** Stacked (single-column) — constrained by 400×600 window
- **Pattern:** Fixed header → scrollable content → sticky action bar
- **Max content width:** 100% (window is already constrained)

## Border Radius
| Element | Classic | Cyber | Hybrid |
|---------|---------|-------|--------|
| Buttons/Inputs | 8px | 6px | 8px |
| Cards/Modals | 12px | 8px | 10px |
| Tags/Badges | 9999px | 4px | 6px |
| Icons/Avatars | 8px | 6px | 8px |

## Motion
- **Approach:** Minimal-functional
- **Duration:** 150ms (hover), 200ms (state change)
- **Easing:** ease-out (cubic-bezier(0.16, 1, 0.3, 1))
- **Only functional animations:** button feedback, state transitions, fade in/out
- **No decorative motion**

## Theme Implementation

### CSS Architecture
```css
/* Root defaults (Classic) */
:root {
  --color-primary: #0EA5E9;
  /* ... */
}

/* Theme overrides via data attribute */
[data-theme="cyber"] {
  --color-primary: #00F0FF;
  /* ... */
}

[data-theme="hybrid"] {
  --color-primary: #06B6D4;
  /* ... */
}
```

### Theme Switching
- Store in `localStorage` key `pwdvault-theme`
- Read on app start, apply `data-theme` attribute to `<html>`
- Settings screen provides dropdown: Classic / Cyber / Hybrid
- CSS transitions on theme change (0.3s ease on background/color)

### Font Loading
```html
<!-- Classic + Hybrid -->
<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">

<!-- Cyber -->
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=Space+Mono:wght@400;700&display=swap" rel="stylesheet">
```

Optimization: dynamically load font based on active theme to avoid unused font downloads.

## Decisions Log
| Date | Decision | Rationale |
|------|----------|-----------|
| 2026-04-14 | Initial design system created | Created by /design-consultation based on competitive research (1Password, Bitwarden, KeePassXC) and three-direction exploration |
| 2026-04-14 | Three-theme system adopted | User requested all three directions (Classic, Cyber, Hybrid) as switchable options |
| 2026-04-14 | Cyan primary chosen over purple | Purple is overused in AI era; cyan is distinctive in password manager category |
| 2026-04-14 | Plus Jakarta Sans chosen as default body font | Geometric clarity similar to Inter but with more character; not on the overused list |
| 2026-04-14 | Compact spacing (4px base) | Optimized for 400×600 window constraint |
