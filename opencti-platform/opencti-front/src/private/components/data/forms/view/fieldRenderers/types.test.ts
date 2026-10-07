import { describe, expect, it } from 'vitest';
import type { FieldRenderer, FieldRendererContext } from './types';

const context: FieldRendererContext = {
  field: {
    id: 'title-field',
    name: 'title',
    label: 'Title',
    description: 'The form title',
    type: 'text',
    required: true,
    width: 'full',
    attributeMapping: {
      entity: 'main_entity',
      attributeName: 'title',
      mappingType: 'direct',
    },
    defaultValue: 'Untitled',
    isReadOnly: false,
  },
  values: { title: 'hello' },
  errors: { title: 'required' },
  touched: { title: true },
  setFieldValue: (field, value) => {
    void field;
    void value;
  },
  entitySettings: {
    edges: [
      {
        node: {
          id: 'main-entity',
          target_type: 'MainEntity',
          mandatoryAttributes: ['title'],
          attributesDefinitions: [
            {
              type: 'string',
              name: 'title',
              label: 'Title',
              mandatory: true,
            },
          ],
        },
      },
    ],
  },
  fieldPrefix: 'main',
  useGridLayout: true,
  getNestedValue: (object, path) => path.split('.').reduce<unknown>(
    (value, key) => (value as Record<string, unknown> | undefined)?.[key],
    object,
  ),
};

describe('FieldRendererContext / FieldRenderer', () => {
  it('accepts a fully populated context matching the exported contract', () => {
    expect(context.values.title).toBe('hello');
    expect(context.errors.title).toBe('required');
    expect(context.touched.title).toBe(true);
    expect(context.getNestedValue({ metadata: { source: 'form' } }, 'metadata.source')).toBe('form');
  });

  it('allows a FieldRenderer to be invoked with a valid context', () => {
    const renderer: FieldRenderer = (fieldContext) => `rendered:${fieldContext.field.name}`;

    expect(renderer(context)).toBe('rendered:title');
  });
});
