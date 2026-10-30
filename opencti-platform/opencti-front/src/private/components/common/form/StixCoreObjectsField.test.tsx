import { fireEvent, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Formik, useFormikContext } from 'formik';
import { describe, expect, it, vi } from 'vitest';
import testRender from '../../../../utils/tests/test-render';
import { DeferredCreationContext, useDeferredCreation } from '../../../../utils/hooks/useDeferredCreation';
import StixCoreObjectsField from './StixCoreObjectsField';

vi.mock('../../../../utils/hooks/useAttributes', () => ({
  __esModule: true,
  default: () => ({ stixCoreObjectTypes: ['Attack-Pattern'], stixDomainObjectTypes: ['Attack-Pattern'], stixCyberObservableTypes: [] }),
}));

// A creation form submitted in deferred mode: the creation is captured, then the dialog closes twice,
// as the real forms do (resetForm calls onReset, then onCompleted, both bound to the close of the dialog)
vi.mock('../stix_domain_objects/StixDomainObjectCreation', () => ({
  __esModule: true,
  default: ({ open, handleClose }: { open: boolean; handleClose: () => void }) => {
    const { isDeferredMode, captureInput } = useDeferredCreation();
    if (!open) return null;
    const submit = () => {
      // useApiMutation only captures the creation in deferred mode
      if (isDeferredMode) captureInput({ name: 'New TTP' });
      handleClose();
      handleClose();
    };
    return <button type="button" onClick={submit}>Submit creation</button>;
  },
}));

vi.mock('../../observations/stix_cyber_observables/StixCyberObservableCreation', () => ({ __esModule: true, default: () => null }));

// The search of existing objects returns nothing
vi.mock('../../../../relay/environment', async (importOriginal) => ({
  ...(await importOriginal<object>()),
  fetchQuery: () => ({ toPromise: () => Promise.resolve({}) }),
}));

const Values = () => {
  const { values } = useFormikContext<Record<string, unknown>>();
  return <pre data-testid="values">{JSON.stringify(values)}</pre>;
};

const renderField = (multiple: boolean) => testRender(
  <Formik initialValues={{ ttps: multiple ? [] : '' }} onSubmit={() => {}}>
    <>
      <StixCoreObjectsField name="ttps" types={['Attack-Pattern']} multiple={multiple} deferCreation />
      <Values />
    </>
  </Formik>,
);

// The field inside a creation dialog of a form, which is deferred already
const renderNestedField = () => testRender(
  <DeferredCreationContext.Provider value={{ isDeferredMode: true, captureInput: () => {}, registerPending: () => '', getPending: () => undefined }}>
    <Formik initialValues={{ ttps: [] }} onSubmit={() => {}}>
      <>
        <StixCoreObjectsField name="ttps" types={['Attack-Pattern']} multiple />
        <Values />
      </>
    </Formik>
  </DeferredCreationContext.Provider>,
);

const createInDialog = async () => {
  await userEvent.type(screen.getByRole('combobox'), 'New TTP');
  fireEvent.click(await screen.findByRole('option', { name: /Create/ }));
  fireEvent.click(screen.getByRole('button', { name: 'Submit creation' }));
};

const selection = () => JSON.parse(screen.getByTestId('values').textContent ?? '{}').ttps;

describe('StixCoreObjectsField - deferred creation', () => {
  it.each([true, false])('should keep the object created in the form selected when the dialog closes twice (multiple: %s)', async (multiple) => {
    renderField(multiple);
    // the creation option of the search, which restores the previous selection when the dialog is cancelled
    await createInDialog();
    const selected = [selection()].flat();
    expect(selected).toHaveLength(1);
    expect(selected[0]).toMatchObject({ label: 'New TTP', type: 'Attack-Pattern', isPendingCreation: true });
  });

  it('should defer the creation of a field inside a creation dialog of a form, without the prop', async () => {
    renderNestedField();
    await createInDialog();
    expect(selection()).toEqual([expect.objectContaining({ label: 'New TTP', type: 'Attack-Pattern', isPendingCreation: true })]);
  });
});
