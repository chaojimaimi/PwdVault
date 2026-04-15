import React from 'react';
import { render, screen } from '@testing-library/react';
import { it, expect } from 'vitest';

function HookComp() {
  const [n] = React.useState(0);
  return <div>n{n}</div>;
}

it('hooks sanity: useState works', () => {
  render(<HookComp />);
  expect(screen.getByText('n0')).toBeTruthy();
});
