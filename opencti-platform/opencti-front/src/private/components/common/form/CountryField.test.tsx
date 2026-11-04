import { describe, it, expect, vi, beforeEach, Mock } from 'vitest';
import React from 'react';
import { screen, waitFor } from '@testing-library/react';
import { Formik, Form } from 'formik';
import testRender from '../../../../utils/tests/test-render';
import { fetchQuery } from '../../../../relay/environment';
import CountryField from './CountryField';
import { FieldOption } from '../../../../utils/field';

vi.mock('../../../../relay/environment', async () => {
  const actual = await vi.importActual('../../../../relay/environment');
  return {
    ...actual,
    fetchQuery: vi.fn(),
  };
});

const france: FieldOption = { label: 'France', value: 'country-france' };

const renderCountryField = (
  props: { required?: boolean; onChange?: (name: string, value: FieldOption | null) => void } = {},
  initialValue: FieldOption | null = france,
) => {
  return testRender(
    <Formik initialValues={{ bornIn: initialValue }} onSubmit={vi.fn()}>
      <Form>
        <CountryField
          id="PlaceOfBirth"
          name="bornIn"
          label="Place of Birth"
          {...props}
        />
      </Form>
    </Formik>,
  );
};

describe('CountryField', () => {
  const fetchQueryMock = fetchQuery as Mock;

  beforeEach(() => {
    vi.clearAllMocks();
    fetchQueryMock.mockReturnValue({
      toPromise: () => Promise.resolve({ countries: { edges: [] } }),
    });
  });

  it('shows a clear button on an optional field holding a value', () => {
    renderCountryField();
    expect(screen.getByRole('button', { name: 'Clear' })).toBeInTheDocument();
  });

  it('empties the value and reports null when the clear button is clicked', async () => {
    const onChange = vi.fn();
    const { user } = renderCountryField({ onChange });
    await user.click(screen.getByRole('button', { name: 'Clear' }));
    await waitFor(() => {
      expect(onChange).toHaveBeenCalledWith('bornIn', null);
    });
  });

  it('shows no clear button on a mandatory field', () => {
    renderCountryField({ required: true });
    expect(screen.queryByRole('button', { name: 'Clear' })).not.toBeInTheDocument();
  });

  it('shows no clear button while the field is empty', () => {
    renderCountryField({}, null);
    expect(screen.queryByRole('button', { name: 'Clear' })).not.toBeInTheDocument();
  });
});
