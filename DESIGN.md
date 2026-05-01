# Design System — PwdVault

## Product Context
- **What this is:** Local-first, encrypted password manager built with Tauri v2 + React
- **Who it's for:** Privacy-conscious desktop users who want control over their credentials
- **Space/industry:** Security tools (1Password, Bitwarden, KeePassXC)
- **Project type:** Desktop app (compact 400×600 window) with browser extension

## Aesthetic Direction
- **Direction:** Trust & Security — deep navy + teal accent
- **Decoration level:** Minimal — typography and color do all the work
- **Mood:** Precise, trustworthy, purpose-built. Not decorative, not generic.
- **Reference products:** 1Password (warmth), Bitwarden (open trust)

## Theme System

PwdVault supports two themes: **Light** (default) and **Dark**. The system automatically follows the OS preference when no explicit choice is saved.

### Architecture

- **`:root`** defines all shared tokens (typography, spacing, radius, shadows, animation, fonts)
- **`[data-theme="light"]`** and **`[data-theme="dark"]`** override only color tokens

### Theme: Light (Default)

Professional security aesthetic with navy primary and teal accent.

| Token | Value | Usage |
|-------|-------|-------|
| `--color-primary` | `#1E3A5F` | Buttons, links, accents |
| `--color-primary-hover` | `#153050` | Hover states |
| `--color-primary-dim` | `rgba(30, 58, 95, 0.07)` | Light backgrounds, badges |
| `--color-primary-border` | `rgba(30, 58, 95, 0.20)` | Focused borders |
| `--color-accent` | `#0D9488` | Secondary accent |
| `--color-accent-dim` | `rgba(13, 148, 136, 0.10)` | Accent backgrounds |
| `--gradient-icon` | `linear-gradient(135deg, #1E3A5F, #0D9488)` | Entry icons |
| `--color-bg` | `#F8FAFC` | Main background |
| `--color-surface` | `#FFFFFF` | Cards, panels |
| `--color-input` | `#EDEEF2` | Input backgrounds |
| `--color-text` | `#0F172A` | Primary text |
| `--color-text-secondary` | `#475569` | Secondary text |
| `--color-text-muted` | `#94A3B8` | Muted text, placeholders |
| `--color-border` | `rgba(0, 0, 0, 0.06)` | Subtle borders |
| `--color-border-light` | `rgba(0, 0, 0, 0.10)` | Emphasis borders |
| `--color-success` | `#059669` | Success states |
| `--color-danger` | `#DC2626` | Danger, delete |
| `--color-danger-hover` | `#B91C1C` | Danger hover |
| `--color-danger-dim` | `rgba(220, 38, 38, 0.07)` | Danger backgrounds |
| `--color-warning` | `#D97706` | Warning states |

### Theme: Dark

Modern deep dark with teal primary and lighter accents.

| Token | Value | Usage |
|-------|-------|-------|
| `--color-primary` | `#14B8A6` | Buttons, links, accents |
| `--color-primary-hover` | `#0D9488` | Hover states |
| `--color-primary-dim` | `rgba(20, 184, 166, 0.10)` | Light backgrounds |
| `--color-primary-border` | `rgba(20, 184, 166, 0.25)` | Focused borders |
| `--color-accent` | `#5EEAD4` | Secondary accent |
| `--color-accent-dim` | `rgba(94, 234, 212, 0.10)` | Accent backgrounds |
| `--gradient-icon` | `linear-gradient(135deg, #14B8A6, #5EEAD4)` | Entry icons |
| `--color-bg` | `#020203` | Main background |
| `--color-surface` | `#0A0A0C` | Cards, panels |
| `--color-input` | `#16161E` | Input backgrounds |
| `--color-text` | `#EDEDEF` | Primary text |
| `--color-text-secondary` | `#8A8F98` | Secondary text |
| `--color-text-muted` | `#5C6370` | Muted text |
| `--color-border` | `rgba(255, 255, 255, 0.08)` | Subtle borders |
| `--color-border-light` | `rgba(255, 255, 255, 0.12)` | Emphasis borders |
| `--color-success` | `#34D399` | Success states |
| `--color-danger` | `#F87171` | Danger, delete |
| `--color-danger-hover` | `#EF4444` | Danger hover |
| `--color-danger-dim` | `rgba(248, 113, 113, 0.10)` | Danger backgrounds |
| `--color-warning` | `#FBBF24` | Warning states |

## Shared Tokens

### Typography

| Token | Value | Usage |
|-------|-------|-------|
| `--font-body` | `'Inter', system-ui, -apple-system, sans-serif` | Body text |
| `--font-mono` | `'JetBrains Mono', ui-monospace, monospace` | Passwords, codes |
| `--text-h1` | `1.5rem` | Page titles |
| `--text-h2` | `1.125rem` | Section titles |
| `--text-body` | `0.875rem` | Body text |
| `--text-label` | `0.75rem` | Labels, hints |
| `--text-micro` | `0.6875rem` | Tiny text |
| `--text-mono` | `0.8125rem` | Monospace text |

### Spacing (4px base unit)

| Token | Value |
|-------|-------|
| `--space-xs` | `4px` |
| `--space-sm` | `8px` |
| `--space-md` | `12px` |
| `--space-lg` | `16px` |
| `--space-xl` | `24px` |
| `--space-2xl` | `32px` |

### Border Radius

| Token | Value | Usage |
|-------|-------|-------|
| `--radius-sm` | `6px` | Buttons, inputs |
| `--radius-md` | `8px` | Cards |
| `--radius-lg` | `12px` | Modals |
| `--radius-tag` | `9999px` | Tags, pills |

### Animation

| Token | Value |
|-------|-------|
| `--duration-fast` | `150ms` |
| `--duration-normal` | `200ms` |
| `--duration-slow` | `300ms` |
| `--easing-out` | `cubic-bezier(0.16, 1, 0.3, 1)` |

## Accessibility

- All interactive elements have `:focus-visible` outlines (`2px solid var(--color-primary)`)
- `prefers-reduced-motion` disables all animations
- Touch devices show entry actions without hover
- Form inputs use `<label>` with `htmlFor`/`id` associations
- Icon buttons use `aria-label`
- Entry items use `role="list"`/`role="listitem"` with `tabIndex` and `aria-label`
- Modals use `role="dialog"` and `aria-modal="true"`

## CSS File Structure

```
src/styles/
├── themes.css        ← Design tokens (shared + Light/Dark color overrides)
├── base.css          ← Global reset, scrollbar, selection, accessibility, .screen, .loading
├── components.css    ← Buttons, inputs, modals, toasts, strength meter, icons, tags
├── screens.css       ← Entry/generator screen layouts, field groups, option rows
├── vault.css         ← Vault container, search, group tabs, entry list
├── groups.css        ← Group manager cards and actions
└── settings.css      ← Settings sections, theme selector, import/export fields
```
