import { screen } from '@testing-library/react';
import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import testRender from '../../../../utils/tests/test-render';
import EETooltip from './EETooltip';

// Non-enterprise-edition path: EETooltip wraps `children` in a focusable
// `role="button"` span that opens the feedback/agreement flow instead of
// whatever the child would normally do.
vi.mock('../../../../utils/hooks/useEnterpriseEdition', () => ({ default: () => false }));
vi.mock('../../../../utils/hooks/useGranted', () => ({
  default: () => false,
  SETTINGS_SETPARAMETERS: 'SETTINGS_SETPARAMETERS',
}));
vi.mock('../../../../utils/hooks/useAuth', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../utils/hooks/useAuth')>()),
  default: () => ({ settings: { id: 'settings-id' } }),
}));
vi.mock('../../../../utils/hooks/useAI', () => ({ default: () => ({ enabled: false, configured: false }) }));
// Both dialogs are Relay-bound and irrelevant to what this asserts.
vi.mock('../../cases/feedbacks/FeedbackCreation', () => ({ default: () => null }));
vi.mock('./EnterpriseEditionAgreement', () => ({ default: () => null }));

describe('EETooltip', () => {
  it('does not create a second tab stop for an already-focusable child', () => {
    testRender(
      <EETooltip title="Some EE feature">
        <button type="button">Do something</button>
      </EETooltip>,
    );

    // Both the wrapping span and the child button carry role="button" and
    // the same accessible name, but only the span should be in the tab
    // order (tabIndex=0); the child must be pulled out (tabIndex=-1) so Tab
    // lands on exactly one control for this action, not two.
    // MUI Tooltip clones an aria-label (matching the tooltip title) onto the
    // wrapping span, so it and the child button have different accessible
    // names; only the span should be in the tab order (tabIndex=0), and the
    // child must be pulled out (tabIndex=-1) so Tab lands on exactly one
    // control for this action, not two.
    const wrapper = screen.getByRole('button', { name: 'Some EE feature' });
    const child = screen.getByRole('button', { name: 'Do something' });
    expect(wrapper.tagName).toBe('SPAN');
    expect(wrapper).toHaveAttribute('tabIndex', '0');
    expect(child.tagName).toBe('BUTTON');
    expect(child).toHaveAttribute('tabIndex', '-1');
  });
});
