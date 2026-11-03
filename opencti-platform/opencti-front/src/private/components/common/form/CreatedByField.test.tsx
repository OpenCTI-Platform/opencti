import { screen } from '@testing-library/react';
import { Formik } from 'formik';
import { describe, expect, it, vi } from 'vitest';
import { DeferredCreationContext } from '../../../../utils/hooks/useDeferredCreation';
import testRender from '../../../../utils/tests/test-render';
import CreatedByField from './CreatedByField';

// The create affordance is what is under test: reduce the combobox to whether it was given one
vi.mock('../../../../components/ComboboxField', () => ({
  __esModule: true,
  default: ({ openCreate }: { openCreate?: () => void }) => <div data-testid="combobox" data-can-create={String(!!openCreate)} />,
}));

vi.mock('../identities/IdentityCreation', () => ({
  __esModule: true,
  default: () => null,
}));

const renderField = (isDeferredMode?: boolean) => {
  const field = (
    <Formik initialValues={{ createdBy: null }} onSubmit={() => {}}>
      <CreatedByField name="createdBy" setFieldValue={vi.fn()} />
    </Formik>
  );
  return testRender(isDeferredMode === undefined
    ? field
    : (
        <DeferredCreationContext.Provider value={{ isDeferredMode, captureInput: vi.fn(), registerPending: vi.fn(), getPending: vi.fn() }}>
          {field}
        </DeferredCreationContext.Provider>
      ));
};

describe('CreatedByField', () => {
  it('offers to create an author by default', () => {
    renderField();
    expect(screen.getByTestId('combobox').getAttribute('data-can-create')).toBe('true');
  });

  it('does not offer to create an author in a form intake', () => {
    renderField(true);
    expect(screen.getByTestId('combobox').getAttribute('data-can-create')).toBe('false');
  });
});
