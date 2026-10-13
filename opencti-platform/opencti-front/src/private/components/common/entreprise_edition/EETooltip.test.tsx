import { act, fireEvent, screen } from '@testing-library/react';
import React, { useState } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import testRender from '../../../../utils/tests/test-render';
import EETooltip from './EETooltip';

// Gated paths (no Enterprise Edition, or AI not configured): EETooltip wraps
// `children` in a focusable `role="button"` span that opens the
// feedback/agreement flow, or the "enable AI" dialog, instead of whatever the
// child would normally do.
const state = vi.hoisted(() => ({ isEnterpriseEdition: false }));
vi.mock('../../../../utils/hooks/useEnterpriseEdition', () => ({ default: () => state.isEnterpriseEdition }));
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

// A control enabled after the gate mounted, as a form does once its data loads
const EnabledLater = () => {
  const [enabled, setEnabled] = useState(false);
  return (
    <>
      <EETooltip title="Some EE feature">
        <span><button type="button" disabled={!enabled}>Do something</button></span>
      </EETooltip>
      <button type="button" onClick={() => setEnabled(true)}>Enable</button>
    </>
  );
};

describe('EETooltip', () => {
  beforeEach(() => {
    state.isEnterpriseEdition = false;
  });

  it.each([
    ['a control', <button key="direct" type="button">Do something</button>],
    ['a control nested in a wrapper', <span key="nested"><span><button type="button">Do something</button></span></span>],
    ['a disabled control', <button key="disabled" type="button" disabled>Do something</button>],
  ])('is the only tab stop around %s, named by its title', async (_, child) => {
    const { user } = testRender(
      <>
        <EETooltip title="Some EE feature">{child}</EETooltip>
        <button type="button">Elsewhere</button>
      </>,
    );

    await user.tab();
    expect(screen.getByRole('button', { name: 'Some EE feature' })).toHaveFocus();
    await user.tab();
    expect(screen.getByRole('button', { name: 'Elsewhere' })).toHaveFocus();
    // The wrapped control is only the gate's look: hidden from assistive tech
    expect(screen.queryByRole('button', { name: 'Do something' })).not.toBeInTheDocument();
  });

  it('keeps a control enabled later out of the tab order', async () => {
    const { user } = testRender(<EnabledLater />);

    await user.click(screen.getByRole('button', { name: 'Enable' }));
    await act(() => Promise.resolve()); // let the observer run
    expect(screen.getByText('Do something')).toBeEnabled();
    expect(screen.getByText('Do something')).toHaveAttribute('tabindex', '-1');
  });

  it('is named even without a title', () => {
    testRender(
      <EETooltip>
        <button type="button">Do something</button>
      </EETooltip>,
    );

    expect(screen.getByRole('button', { name: 'Enterprise Edition' })).toHaveAttribute('tabindex', '0');
  });

  it('opens the EE flow instead of running the wrapped control\'s own action', async () => {
    const childAction = vi.fn();
    const { user } = testRender(
      <EETooltip title="Some EE feature">
        <button type="button" onClick={childAction}>Do something</button>
      </EETooltip>,
    );

    // A mouse click lands on the child itself: the wrapper must stop it in the capture phase
    await user.click(screen.getByText('Do something'));
    fireEvent.keyDown(screen.getByText('Do something'), { key: 'Enter' });
    await user.tab();
    await user.keyboard('{Enter}');
    expect(childAction).not.toHaveBeenCalled();
  });

  it('opens the "enable AI" dialog instead of running the wrapped control\'s own action', async () => {
    state.isEnterpriseEdition = true;
    const childAction = vi.fn();
    const { user } = testRender(
      <EETooltip title="Some AI feature" forAi>
        <span><button type="button" onClick={childAction}>Ask AI</button></span>
      </EETooltip>,
    );

    await user.tab();
    expect(screen.getByRole('button', { name: 'Some AI feature' })).toHaveFocus();
    await user.keyboard('{Enter}');
    expect(childAction).not.toHaveBeenCalled();
    expect(await screen.findByText('Enable AI powered platform')).toBeInTheDocument();
  });
});
