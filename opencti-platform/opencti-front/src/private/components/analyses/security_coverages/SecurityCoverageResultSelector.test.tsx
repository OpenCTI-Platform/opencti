import { describe, it, expect, vi } from 'vitest';
import React from 'react';
import { screen } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import SecurityCoverageResultSelector from './SecurityCoverageResultSelector';

const twoOptions = [
  { value: 'scr-a', label: 'OAEV Lyon' },
  { value: 'scr-b', label: 'OAEV Paris' },
];

describe('SecurityCoverageResultSelector', () => {
  it('is displayed even without any result', () => {
    testRender(<SecurityCoverageResultSelector options={[]} value={null} onChange={vi.fn()} />);
    expect(screen.getByRole('combobox', { name: 'Security Coverage Result' })).toHaveTextContent('Security Coverage Result');
  });
  it('is displayed with a single result', () => {
    testRender(<SecurityCoverageResultSelector options={[{ value: 'scr-a', label: 'OAEV Lyon' }]} value={null} onChange={vi.fn()} />);
    expect(screen.getByRole('combobox', { name: 'Security Coverage Result' })).toBeInTheDocument();
  });
  it('shows the Security Coverage Result label while all results are selected', () => {
    testRender(<SecurityCoverageResultSelector options={twoOptions} value={null} onChange={vi.fn()} />);
    expect(screen.getByRole('combobox', { name: 'Security Coverage Result' })).toHaveTextContent('Security Coverage Result');
  });
  it('shows the selected result label', () => {
    testRender(<SecurityCoverageResultSelector options={twoOptions} value="scr-b" onChange={vi.fn()} />);
    expect(screen.getByRole('combobox', { name: 'Security Coverage Result' })).toHaveTextContent('OAEV Paris');
  });
});
