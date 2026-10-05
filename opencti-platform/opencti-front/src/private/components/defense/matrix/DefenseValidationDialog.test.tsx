import React from 'react';
import { screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import testRender from '../../../../utils/tests/test-render';
import DefenseValidationDialog from './DefenseValidationDialog';

const TECHNIQUES = [{ id: 'ap-1', name: 'Phishing', x_mitre_id: 'T1566' }];

describe('Defense validation dialog', () => {
  it('says how many techniques of the scope the request leaves out and where to select them', () => {
    testRender(<DefenseValidationDialog open onClose={vi.fn()} techniques={TECHNIQUES} deferredCount={57} threats={[]} />);
    const notice = screen.getByTestId('defense-validation-deferred');
    expect(notice.textContent).toContain('57 more techniques of this scope are not part of this request.');
    expect(notice.textContent).toContain('A validation request holds at most 200 techniques');
    expect(screen.getByRole('link', { name: 'Open the Gaps tab' }).getAttribute('href')).toBe('/dashboard/defense/matrix/gaps');
  });

  it('shows no notice when the request holds the whole scope', () => {
    testRender(<DefenseValidationDialog open onClose={vi.fn()} techniques={TECHNIQUES} threats={[]} />);
    expect(screen.getByTestId('defense-validation-count').textContent).toBe('1 technique');
    expect(screen.queryByTestId('defense-validation-deferred')).toBeNull();
  });
});
