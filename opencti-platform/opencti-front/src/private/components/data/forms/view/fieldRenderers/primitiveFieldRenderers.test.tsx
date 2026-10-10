import React from 'react';
import { Formik } from 'formik';
import { screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { fieldRendererRegistry } from './registry';
import './primitiveFieldRenderers';
import type { FieldRendererContext } from './types';
import type { FormFieldDefinition } from '../../Form.d';
import testRender, { createMockUserContext } from '../../../../../../utils/tests/test-render';

const createContext = (field: Partial<FormFieldDefinition>): FieldRendererContext => ({
  field: {
    id: 'field-1',
    name: 'title',
    label: 'Title',
    type: 'text',
    required: false,
    isMandatory: false,
    attributeMapping: {
      entity: 'main_entity',
      attributeName: 'title',
    },
    ...field,
  },
  values: { title: '' },
  errors: {},
  touched: {},
  setFieldValue: () => {},
  fieldPrefix: undefined,
  useGridLayout: false,
  getNestedValue: () => undefined,
});

const renderField = (type: string, field: Partial<FormFieldDefinition> = {}) => {
  const renderer = fieldRendererRegistry[type];
  if (!renderer) {
    throw new Error(`No renderer registered for ${type}`);
  }

  const context = createContext({ type, ...field });
  return testRender(
    <Formik initialValues={{ title: type === 'checkbox' ? false : '' }} onSubmit={() => {}}>
      {() => renderer(context)}
    </Formik>,
    { userContext: createMockUserContext() },
  );
};

describe('primitive field renderers', () => {
  it('registers all primitive field renderer adapters', () => {
    expect(fieldRendererRegistry.text).toBeDefined();
    expect(fieldRendererRegistry.textarea).toBeDefined();
    expect(fieldRendererRegistry.number).toBeDefined();
    expect(fieldRendererRegistry.checkbox).toBeDefined();
    expect(fieldRendererRegistry.toggle).toBeDefined();
    expect(fieldRendererRegistry.default).toBeDefined();
  });

  it('renders a text field through Formik', () => {
    renderField('text');

    expect(screen.getByRole('textbox', { name: 'Title' })).toBeTruthy();
  });

  it('renders a checkbox through Formik', () => {
    renderField('checkbox');

    expect(screen.getByLabelText('Title')).toBeTruthy();
  });

  it('renders the default field through Formik', () => {
    renderField('default', { label: 'Fallback field' });

    expect(screen.getByRole('textbox', { name: 'Fallback field' })).toBeTruthy();
  });

  it('renders a textarea field through Formik', () => {
    renderField('textarea');

    expect(screen.getByRole('button', { name: 'Write' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Preview' })).toBeTruthy();
  });

  it('renders a number field through Formik', () => {
    renderField('number');

    expect(screen.getByRole('spinbutton', { name: 'Title' })).toBeTruthy();
  });

  it('renders a toggle field through Formik', () => {
    renderField('toggle');

    expect(screen.getByRole('switch', { name: 'Title' })).toBeTruthy();
  });

  it('toggles the checkbox value when clicked', async () => {
    const { user } = renderField('checkbox');
    const checkbox = screen.getByLabelText('Title');

    expect(checkbox).not.toBeChecked();
    await user.click(checkbox);
    expect(checkbox).toBeChecked();
  });

  it('toggles the switch value when clicked', async () => {
    const { user } = renderField('toggle');
    const toggle = screen.getByRole('switch', { name: 'Title' });

    expect(toggle).not.toBeChecked();
    await user.click(toggle);
    expect(toggle).toBeChecked();
  });

  it('prefixes the field name when a fieldPrefix is provided', () => {
    const renderer = fieldRendererRegistry.text;
    const context: FieldRendererContext = {
      field: {
        id: 'field-1',
        name: 'title',
        label: 'Title',
        type: 'text',
        required: false,
        isMandatory: true,
        attributeMapping: { entity: 'entity-1', attributeName: 'title' },
        description: 'Some helper text',
      },
      values: { metadata: { title: '' } },
      errors: {},
      touched: {},
      setFieldValue: () => {},
      fieldPrefix: 'metadata',
      useGridLayout: false,
      getNestedValue: () => undefined,
    };

    testRender(
      <Formik initialValues={{ metadata: { title: '' } }} onSubmit={() => {}}>
        {() => renderer!(context)}
      </Formik>,
      { userContext: createMockUserContext() },
    );

    const input = screen.getByRole('textbox', { name: 'Title' }) as HTMLInputElement;
    expect(input).toHaveAttribute('name', 'metadata.title');
    expect(input).toBeRequired();
    expect(screen.getByText('Some helper text')).toBeTruthy();
  });
});
