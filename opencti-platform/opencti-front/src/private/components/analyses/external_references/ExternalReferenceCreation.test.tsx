import { screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { DeferredCreationContext, PendingObjectData } from '../../../../utils/hooks/useDeferredCreation';
import testRender from '../../../../utils/tests/test-render';
import ExternalReferenceCreation from './ExternalReferenceCreation';

describe('ExternalReferenceCreation in a form intake', () => {
  it('keeps the external reference as a pending object and sends nothing', async () => {
    const context = {
      isDeferredMode: true,
      captureInput: vi.fn(),
      registerPending: vi.fn((_data: PendingObjectData) => '__pending__:ref-1'),
      getPending: vi.fn(),
    };
    const creationCallback = vi.fn();
    const handleCloseContextual = vi.fn();
    const { user, relayEnv } = testRender(
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
    await user.click(screen.getByRole('button', { name: 'Create' }));
    await waitFor(() => expect(creationCallback).toHaveBeenCalledTimes(1));
    expect(context.registerPending).toHaveBeenCalledTimes(1);
    expect(context.registerPending.mock.calls[0][0]).toMatchObject({ entityType: 'External-Reference', input: { source_name: 'MITRE' } });
    expect(creationCallback.mock.calls[0][0].externalReferenceAdd).toMatchObject({ source_name: 'MITRE', id: '__pending__:ref-1' });
    expect(handleCloseContextual).toHaveBeenCalled();
    expect(relayEnv.mock.getAllOperations()).toHaveLength(0);
  });
});
