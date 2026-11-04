import { screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { DeferredCreationContext, PendingObjectData } from '../../../../utils/hooks/useDeferredCreation';
import testRender from '../../../../utils/tests/test-render';
import ExternalReferenceCreation from './ExternalReferenceCreation';

describe('ExternalReferenceCreation in a form intake', () => {
  const renderDeferred = () => {
    const context = {
      isDeferredMode: true,
      captureInput: vi.fn(),
      registerPending: vi.fn((_data: PendingObjectData) => '__pending__:ref-1'),
      getPending: vi.fn(),
    };
    const creationCallback = vi.fn();
    const handleCloseContextual = vi.fn();
    const rendered = testRender(
      <DeferredCreationContext.Provider value={context}>
        <ExternalReferenceCreation
          contextual={true}
          display={true}
          inputValue="MITRE"
          openContextual={true}
          handleCloseContextual={handleCloseContextual}
          creationCallback={creationCallback}
        />
      </DeferredCreationContext.Provider>,
    );
    return { ...rendered, context, creationCallback, handleCloseContextual };
  };

  it('keeps the external reference as a pending object and sends nothing', async () => {
    const { user, relayEnv, context, creationCallback, handleCloseContextual } = renderDeferred();
    await user.type(screen.getByRole('textbox', { name: 'URL' }), 'https://attack.mitre.org');
    await user.click(screen.getByRole('button', { name: 'Create' }));
    await waitFor(() => expect(creationCallback).toHaveBeenCalledTimes(1));
    expect(context.registerPending).toHaveBeenCalledTimes(1);
    expect(context.registerPending.mock.calls[0][0]).toMatchObject({ entityType: 'External-Reference', input: { source_name: 'MITRE', url: 'https://attack.mitre.org' } });
    expect(creationCallback.mock.calls[0][0].externalReferenceAdd).toMatchObject({ source_name: 'MITRE', id: '__pending__:ref-1' });
    expect(handleCloseContextual).toHaveBeenCalled();
    expect(relayEnv.mock.getAllOperations()).toHaveLength(0);
  });

  it('requires a URL or an external ID, which the import needs to identify the reference', async () => {
    const { user, context, creationCallback } = renderDeferred();
    await user.click(screen.getByRole('button', { name: 'Create' }));
    expect(await screen.findByText('A URL or an external ID is required')).toBeTruthy();
    expect(context.registerPending).not.toHaveBeenCalled();
    await user.type(screen.getByRole('textbox', { name: 'External ID' }), 'T1059');
    await user.click(screen.getByRole('button', { name: 'Create' }));
    await waitFor(() => expect(creationCallback).toHaveBeenCalledTimes(1));
    expect(context.registerPending.mock.calls[0][0]).toMatchObject({ input: { source_name: 'MITRE', external_id: 'T1059' } });
  });
});
