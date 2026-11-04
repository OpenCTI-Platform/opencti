import { screen, act, waitFor } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { MockPayloadGenerator } from 'relay-test-utils';
import testRender from '../../../../utils/tests/test-render';
import { DeferredCreationContext } from '../../../../utils/hooks/useDeferredCreation';
import StixDomainObjectCreation from './StixDomainObjectCreation';

describe('StixDomainObjectCreation', () => {
  // An Observed-Data cannot be created in a form: no type is left, the dialog must still render
  it('should render an empty type list in a form without crashing', async () => {
    const { relayEnv } = testRender(
      <DeferredCreationContext.Provider value={{ isDeferredMode: true, captureInput: () => {}, registerPending: () => '', getPending: () => undefined }}>
        <StixDomainObjectCreation
          display
          open
          speeddial
          handleClose={() => {}}
          stixDomainObjectTypes={['Observed-Data']}
          inputValue=""
          creationCallback={() => {}}
          confidence={undefined}
          defaultCreatedBy={undefined}
          defaultMarkingDefinitions={undefined}
          paginationKey={undefined}
          paginationOptions={undefined}
          onCompleted={undefined}
          isFromBulkRelation={false}
        />
      </DeferredCreationContext.Provider>,
    );
    await waitFor(() => expect(relayEnv.mock.getAllOperations()).toHaveLength(1));
    act(() => {
      relayEnv.mock.resolveMostRecentOperation((operation) => MockPayloadGenerator.generate(operation, {
        SubTypeConnection: () => ({ edges: [{ node: { id: 'observed-data', label: 'Observed-Data' } }] }),
      }));
    });
    expect(await screen.findByRole('combobox', { name: 'Entity type' })).toBeInTheDocument();
  });
});
