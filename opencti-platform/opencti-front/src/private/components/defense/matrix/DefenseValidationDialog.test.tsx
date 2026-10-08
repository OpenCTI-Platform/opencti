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
    expect(screen.queryByTestId('defense-validation-gaps-limit')).toBeNull();
    expect((screen.getByTestId('defense-validation-submit') as HTMLButtonElement).disabled).toBe(false);
  });

  it('refuses a request tracked on more gaps than the platform accepts and says why', () => {
    const techniques = Array.from({ length: 200 }, (_, i) => ({ id: `ap-${i}`, name: `Technique ${i}` }));
    const platforms = Array.from({ length: 10 }, (_, i) => ({ id: `platform-${i}`, name: `Platform ${i}` }));
    testRender(<DefenseValidationDialog open onClose={vi.fn()} techniques={techniques} platforms={platforms} threats={[]} />);
    const notice = screen.getByTestId('defense-validation-gaps-limit');
    expect(notice.textContent).toContain('This request would be tracked on 2200 gaps and a validation request is tracked on at most 2000');
    const submit = screen.getByTestId('defense-validation-submit') as HTMLButtonElement;
    expect(submit.disabled).toBe(true);
    expect(submit.getAttribute('aria-describedby')).toBe('defense-validation-gaps-limit');
  });
});
