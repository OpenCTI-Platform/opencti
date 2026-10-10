import React from 'react';
import { Formik } from 'formik';
import { screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import testRender, { createMockUserContext } from '../../../../../../utils/tests/test-render';
import type { FieldRendererContext } from './types';
import { fieldRendererRegistry } from './registry';
import './choiceFieldRenderers';

vi.mock('../../../../common/form/OpenVocabField', () => ({
  default: ({
    name,
    label,
    type,
    multiple,
  }: {
    name: string;
    label: string;
    type: string;
    multiple: boolean;
  }) => (
    <div data-testid="openvocab-field">
      {`${name}:${label}:${type}:${multiple}`}
    </div>
  ),
}));

vi.mock('@components/observations/TypesField', () => ({
  default: ({
    name,
    label,
    multiple,
  }: {
    name: string;
    label: string;
    multiple: boolean;
  }) => (
    <div data-testid="types-field">
      {`${name}:${label}:${multiple}`}
    </div>
  ),
}));

const createContext = (
  field: Partial<FieldRendererContext['field']> & { type: string },
  overrides: Partial<FieldRendererContext> = {},
): FieldRendererContext => ({
  field: {
    id: 'field-1',
    name: 'choice',
    label: 'Choice',
    required: false,
    isMandatory: false,
    attributeMapping: {
      entity: 'main_entity',
      attributeName: 'choice',
    },
    options: [
      { value: 'one', label: 'One' },
      { value: 'two', label: 'Two' },
    ],
    ...field,
    type: field.type,
  },
  values: { choice: '' },
  errors: {},
  touched: {},
  setFieldValue: () => {},
  fieldPrefix: undefined,
  useGridLayout: false,
  getNestedValue: () => undefined,
  ...overrides,
});

const renderField = (
  type: string,
  field: Partial<FieldRendererContext['field']> = {},
  overrides: Partial<FieldRendererContext> = {},
) => {
  const renderer = fieldRendererRegistry[type];
  if (!renderer) {
    throw new Error(`No renderer registered for ${type}`);
  }

  const context = createContext({ type, ...field }, overrides);
  return testRender(
    <Formik initialValues={{ choice: type === 'multiselect' ? [] : '' }} onSubmit={() => {}}>
      {() => renderer(context)}
    </Formik>,
    { userContext: createMockUserContext() },
  );
};

describe('choice field renderers', () => {
  it('registers renderers for select, multiselect, openvocab, and types', () => {
    expect(fieldRendererRegistry.select).toBeDefined();
    expect(fieldRendererRegistry.multiselect).toBeDefined();
    expect(fieldRendererRegistry.openvocab).toBeDefined();
    expect(fieldRendererRegistry.types).toBeDefined();
  });

  it('renders a select field with the fallback None option', async () => {
    const { user } = renderField('select');

    await user.click(screen.getByRole('combobox'));

    expect(screen.getByRole('option', { name: 'None' })).toBeTruthy();
    expect(screen.getByRole('option', { name: 'One' })).toBeTruthy();
  });

  it('renders a multiselect field with its options', async () => {
    const { user } = renderField('multiselect');

    await user.click(screen.getByRole('combobox'));

    expect(screen.getByRole('option', { name: 'One' })).toBeTruthy();
    expect(screen.getByRole('option', { name: 'Two' })).toBeTruthy();
  });

  it('renders the OpenVocabField adapter directly with mapped props', () => {
    renderField('openvocab', { multiple: true });

    expect(screen.getByTestId('openvocab-field')).toHaveTextContent('choice:Choice::true');
  });

  it('renders the TypesField adapter directly with mapped props', () => {
    renderField('types', { multiple: true });

    expect(screen.getByTestId('types-field')).toHaveTextContent('choice:Choice:true');
  });
});
