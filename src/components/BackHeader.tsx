import type { ReactNode } from 'react';
import { BackIcon } from './Icons';

interface BackHeaderProps {
  title: string;
  onBack: () => void;
  right?: ReactNode;
  headerClass?: string;
}

export function BackHeader({ title, onBack, right, headerClass = 'generator-header' }: BackHeaderProps) {
  return (
    <header className={headerClass}>
      <button className="btn btn-icon" onClick={onBack} aria-label="Go back">
        <BackIcon />
      </button>
      <h2>{title}</h2>
      {right ?? <div className="header-spacer" />}
    </header>
  );
}
