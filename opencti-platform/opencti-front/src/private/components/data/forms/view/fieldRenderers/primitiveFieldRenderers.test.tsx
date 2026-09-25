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
});
