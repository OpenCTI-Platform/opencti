import { screen } from '@testing-library/react';
import { Formik } from 'formik';
import { describe, expect, it, vi } from 'vitest';
import { DeferredCreationContext } from '../../../../utils/hooks/useDeferredCreation';
import testRender from '../../../../utils/tests/test-render';
import CreatedByField from './CreatedByField';

type Option = { label: string; value: string; entity: { x_opencti_aliases?: string[] | null } };
type FilterOptions = (options: Option[], inputValue: string) => Option[];

const combobox = vi.hoisted(() => ({ filterOptions: undefined as FilterOptions | undefined }));

// The create affordance and the option filter are what is under test: reduce the combobox to them
vi.mock('../../../../components/ComboboxField', () => ({
  __esModule: true,
  default: ({ openCreate, filterOptions }: { openCreate?: () => void; filterOptions?: FilterOptions }) => {
    combobox.filterOptions = filterOptions;
    return <div data-testid="combobox" data-can-create={String(!!openCreate)} />;
  },
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

const filigran: Option = { label: 'Filigran', value: 'filigran-id', entity: { x_opencti_aliases: ['Fifi'] } };
const anssi: Option = { label: 'ANSSI', value: 'anssi-id', entity: { x_opencti_aliases: null } };

const filterAuthors = (inputValue: string) => {
  renderField();
  // Without a filter of its own, the combobox matches the label only
  const filter = combobox.filterOptions ?? ((options: Option[], input: string) => options
    .filter((option) => option.label.toLowerCase().includes(input.trim().toLowerCase())));
  return filter([filigran, anssi], inputValue).map((option) => option.label);
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

  it('finds an author by one of its aliases', () => {
    expect(filterAuthors('fif')).toEqual(['Filigran']);
  });

  it('still finds an author by its name', () => {
    expect(filterAuthors('anss')).toEqual(['ANSSI']);
  });

  it('lists every author while the search is blank', () => {
    expect(filterAuthors('  ')).toEqual(['Filigran', 'ANSSI']);
  });
});
