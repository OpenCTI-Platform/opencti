import { screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { DeferredCreationContext, DeferredCreationContextValue } from '../../../../utils/hooks/useDeferredCreation';
import testRender from '../../../../utils/tests/test-render';
import LabelCreation from './LabelCreation';

const renderLabelCreation = (deferred: DeferredCreationContextValue | null) => {
  const creationCallback = vi.fn();
  const handleClose = vi.fn();
  const ui = (
    <LabelCreation
      contextual={true}
      inputValueContextual="phishing"
      required={false}
      open={true}
      creationCallback={creationCallback}
      handleClose={handleClose}
      dryrun={false}
    />
  );
  const rendered = testRender(deferred ? <DeferredCreationContext.Provider value={deferred}>{ui}</DeferredCreationContext.Provider> : ui);
  return { ...rendered, creationCallback, handleClose };
};

describe('LabelCreation in a form intake', () => {
  const deferred = (): DeferredCreationContextValue => ({
    isDeferredMode: true,
    captureInput: vi.fn(),
    registerPending: vi.fn(() => '__pending__:label-1'),
    getPending: vi.fn(),
  });

  it('keeps the label as a pending object, without a color and without any mutation', async () => {
    const context = deferred();
    const { user, relayEnv, creationCallback, handleClose } = renderLabelCreation(context);
    expect(screen.queryByText('Color')).toBeNull();
    await user.click(screen.getByRole('button', { name: 'Create' }));
    await waitFor(() => expect(creationCallback).toHaveBeenCalledTimes(1));
    expect(context.registerPending).toHaveBeenCalledWith({ entityType: 'Label', input: { value: 'phishing' } });
    expect(creationCallback.mock.calls[0][0].labelAdd).toEqual({ value: 'phishing', id: '__pending__:label-1' });
    expect(handleClose).toHaveBeenCalled();
    expect(relayEnv.mock.getAllOperations()).toHaveLength(0);
  });

  it('still asks for a color outside a form intake', async () => {
    const { user, relayEnv, creationCallback } = renderLabelCreation(null);
    expect(screen.getAllByText('Color').length).toBeGreaterThan(0);
    await user.click(screen.getByRole('button', { name: 'Create' }));
    await waitFor(() => expect(screen.getByText('This field is required')).toBeTruthy());
    expect(creationCallback).not.toHaveBeenCalled();
    expect(relayEnv.mock.getAllOperations()).toHaveLength(0);
  });
});
