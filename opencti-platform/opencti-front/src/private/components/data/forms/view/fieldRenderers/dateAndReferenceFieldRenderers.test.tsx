import React from 'react';
import { Formik } from 'formik';
import { cleanup, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import testRender, { createMockUserContext } from '../../../../../../utils/tests/test-render';
import type { FieldRendererContext } from './types';
import { fieldRendererRegistry } from './registry';
import './dateAndReferenceFieldRenderers';

vi.mock('../../../../../../components/DateTimePickerField', () => ({
  default: ({
    field,
    textFieldProps,
    withSeconds,
  }: {
    field: { name: string };
    textFieldProps: { label: string };
    withSeconds: boolean;
  }) => (
    <div data-testid="date-time-picker">
      {`${field.name}:${textFieldProps.label}:${withSeconds}`}
    </div>
  ),
}));

vi.mock('../../../../common/form/CreatedByField', () => ({
  default: ({ name, label, required }: { name: string; label: string; required: boolean }) => (
    <div data-testid="created-by-field">{`${name}:${label}:${required}`}</div>
  ),
}));

vi.mock('../../../../common/form/ObjectMarkingField', () => ({
  default: ({ name, label, required }: { name: string; label: string; required: boolean }) => (
    <div data-testid="object-marking-field">{`${name}:${label}:${required}`}</div>
  ),
}));

vi.mock('../../../../common/form/ObjectLabelField', () => ({
  default: ({
    name,
    required,
    values,
  }: {
    name: string;
    required: boolean;
    values: unknown;
  }) => <div data-testid="object-label-field">{`${name}:${required}:${JSON.stringify(values)}`}</div>,
}));

vi.mock('../../../../common/form/ExternalReferencesField', () => ({
  ExternalReferencesField: ({
    name,
    required,
    values,
  }: {
    name: string;
    required: boolean;
    values: unknown;
  }) => (
    <div data-testid="external-references-field">
      {`${name}:${required}:${JSON.stringify(values)}`}
    </div>
  ),
}));

// Mirrors FormFieldRenderer.tsx's real getNestedValue: dotted paths are always walked, whether
// or not a fieldPrefix is set, since a plain field.name can itself be a dotted path (e.g. for
// parsed/multiple main-entity overrides).
const defaultGetNestedValue = (obj: Record<string, unknown>, path: string): unknown => path
  .split('.')
  .reduce<unknown>((current, key) => {
    if (current && typeof current === 'object' && key in current) {
      return (current as Record<string, unknown>)[key];
    }
    return undefined;
  }, obj);

const createContext = (
  field: Partial<FieldRendererContext['field']> & { type: string },
  overrides: Partial<FieldRendererContext> = {},
): FieldRendererContext => ({
  field: {
    id: 'field-1',
    name: 'reference',
    label: 'Reference',
    required: false,
    isMandatory: false,
    attributeMapping: {
      entity: 'main_entity',
      attributeName: 'reference',
    },
    ...field,
    type: field.type,
  },
  values: { reference: '' },
  errors: {},
  touched: {},
  setFieldValue: () => {},
  fieldPrefix: undefined,
  useGridLayout: false,
  getNestedValue: defaultGetNestedValue,
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
    <Formik initialValues={{ reference: '' }} onSubmit={() => {}}>
      {() => renderer(context)}
    </Formik>,
    { userContext: createMockUserContext() },
  );
};

describe('date and reference field renderers', () => {
  it('registers renderers for date, datetime, createdBy, objectMarking, objectLabel, and externalReferences', () => {
    expect(fieldRendererRegistry.date).toBeDefined();
    expect(fieldRendererRegistry.datetime).toBeDefined();
    expect(fieldRendererRegistry.createdBy).toBeDefined();
    expect(fieldRendererRegistry.objectMarking).toBeDefined();
    expect(fieldRendererRegistry.objectLabel).toBeDefined();
    expect(fieldRendererRegistry.externalReferences).toBeDefined();
  });

  it('renders date and datetime fields through Formik', () => {
    const dateRender = renderField('date');
    expect(dateRender.getByTestId('date-time-picker')).toHaveTextContent(
      'reference:Reference:false',
    );

    cleanup();
    const datetimeRender = renderField('datetime');
    expect(datetimeRender.getByTestId('date-time-picker')).toHaveTextContent(
      'reference:Reference:true',
    );
  });

  it('passes mapped props to createdBy and objectMarking fields', () => {
    renderField('createdBy', {
      name: 'creator',
      label: 'Creator',
      isMandatory: true,
    });
    expect(screen.getByTestId('created-by-field')).toHaveTextContent('creator:Creator:true');

    renderField('objectMarking', {
      name: 'markings',
      label: 'Markings',
      isMandatory: true,
    });
    expect(screen.getByTestId('object-marking-field')).toHaveTextContent('markings:Markings:true');
  });

  it('derives objectLabel values from non-prefixed and prefixed context paths', () => {
    const values = [{ label: 'Public', value: 'marking-1' }];

    const nonPrefixedRender = renderField(
      'objectLabel',
      { name: 'labels' },
      {
        values: { labels: values },
      },
    );
    expect(nonPrefixedRender.getByTestId('object-label-field')).toHaveTextContent(
      `labels:false:${JSON.stringify(values)}`,
    );

    cleanup();
    const prefixedRender = renderField(
      'objectLabel',
      { name: 'labels' },
      {
        values: { metadata: { labels: values } },
        fieldPrefix: 'metadata',
        getNestedValue: (object, path) => path.split('.').reduce<unknown>((current, key) => {
          if (current && typeof current === 'object' && key in current) {
            return (current as Record<string, unknown>)[key];
          }
          return undefined;
        }, object),
      },
    );
    expect(prefixedRender.getByTestId('object-label-field')).toHaveTextContent(
      `metadata.labels:false:${JSON.stringify(values)}`,
    );
  });

  it('passes external reference values and required state to the adapter', () => {
    const values = [{ value: 'external-reference-1' }];

    renderField(
      'externalReferences',
      { name: 'externalReferences', isMandatory: true },
      {
        values: { externalReferences: values },
      },
    );

    expect(screen.getByTestId('external-references-field')).toHaveTextContent(
      `externalReferences:true:${JSON.stringify(values)}`,
    );
  });
});
