import { describe, it, vi, expect, beforeEach } from 'vitest';
import React from 'react';
import { screen } from '@testing-library/react';
import { Formik } from 'formik';
import FormFieldRenderer from './FormFieldRenderer';
import testRender, { createMockUserContext } from '../../../../../utils/tests/test-render';
import { BYPASS } from '../../../../../utils/hooks/useGranted';

const baseField = {
  id: 'f1',
  name: 'title',
  label: 'Title',
  type: 'text',
  required: false,
  isMandatory: false,
  attributeMapping: { entity: 'main_entity', attributeName: 'name' },
};

const renderFieldInFormik = (
  fieldProps: typeof baseField & { isReadOnly?: boolean },
  capabilities: Array<{ name: string }> = [],
) => {
  const userContext = createMockUserContext({
    me: {
      name: 'test-user',
      user_email: 'test@opencti.io',
      capabilities,
    },
  });

  return testRender(
    <Formik initialValues={{ title: '' }} onSubmit={() => {}}>
      {() => (
        <FormFieldRenderer
          field={fieldProps}
          values={{ title: '' }}
          setFieldValue={vi.fn()}
          errors={{}}
          touched={{}}
        />
      )}
    </Formik>,
    { userContext },
  );
};

describe('FormFieldRenderer - isReadOnly', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders the field normally when isReadOnly is false', () => {
    renderFieldInFormik({ ...baseField, isReadOnly: false });
    expect(screen.queryByText('Read-Only')).toBeNull();
    // The text field label should be in the DOM
    expect(screen.getByText('Title')).toBeTruthy();
  });

  it('renders nothing (null) for read-only field when user is not bypass', () => {
    const { container } = renderFieldInFormik(
      { ...baseField, isReadOnly: true },
      [], // no capabilities → not bypass
    );
    expect(container.firstChild).toBeNull();
  });

  it('renders field with Read-Only chip overlay for bypass user', () => {
    renderFieldInFormik(
      { ...baseField, isReadOnly: true },
      [{ name: BYPASS }],
    );
    expect(screen.getByText('Read-Only')).toBeTruthy();
    // The actual field label is still rendered beneath the chip
    expect(screen.getByText('Title')).toBeTruthy();
  });

  it('wraps field in Grid item when useGridLayout is true', () => {
    const userContext = createMockUserContext({
      me: { name: 'test-user', user_email: 'test@opencti.io', capabilities: [] },
    });

    const { container } = testRender(
      <Formik initialValues={{ title: '' }} onSubmit={() => {}}>
        {() => (
          <FormFieldRenderer
            field={{ ...baseField, width: 'half' }}
            values={{ title: '' }}
            setFieldValue={vi.fn()}
            useGridLayout={true}
            errors={{}}
            touched={{}}
          />
        )}
      </Formik>,
      { userContext },
    );

    // Grid item renders a div with MUI grid classes
    expect(container.firstChild).toBeTruthy();
  });
});
