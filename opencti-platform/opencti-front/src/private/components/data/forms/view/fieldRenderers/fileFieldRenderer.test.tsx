import React from 'react';
import { cleanup, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import testRender, { createMockUserContext } from '../../../../../../utils/tests/test-render';
import type { FieldRendererContext } from './types';
import { fieldRendererRegistry } from './registry';
import './fileFieldRenderer';

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
  field: Partial<FieldRendererContext['field']> = {},
  overrides: Partial<FieldRendererContext> = {},
): FieldRendererContext => ({
  field: {
    id: 'field-1',
    name: 'attachments',
    label: 'Attachments',
    type: 'files',
    required: false,
    isMandatory: false,
    attributeMapping: {
      entity: 'main_entity',
      attributeName: 'attachments',
    },
    ...field,
  },
  values: { attachments: [] },
  errors: {},
  touched: {},
  setFieldValue: vi.fn(),
  fieldPrefix: undefined,
  useGridLayout: false,
  getNestedValue: defaultGetNestedValue,
  ...overrides,
});

const renderFilesField = (
  field: Partial<FieldRendererContext['field']> = {},
  overrides: Partial<FieldRendererContext> = {},
) => {
  const renderer = fieldRendererRegistry.files;
  if (!renderer) {
    throw new Error('No renderer registered for files');
  }

  const context = createContext(field, overrides);
  return testRender(<>{renderer(context)}</>, {
    userContext: createMockUserContext(),
  });
};

describe('file field renderer', () => {
  it('registers a renderer for the files field type', () => {
    expect(fieldRendererRegistry.files).toBeDefined();
  });

  it('renders the upload button in single-file mode', () => {
    const { container } = renderFilesField();

    expect(screen.getByRole('button', { name: 'Upload' })).toBeTruthy();
    expect(screen.getByText('Upload file')).toBeTruthy();
    expect(container.querySelector('input[type="file"]')).not.toHaveAttribute('multiple');
  });

  it('renders the upload button in multi-file mode without existing files', () => {
    const { container } = renderFilesField({ multiple: true });

    expect(screen.getByRole('button', { name: 'Upload' })).toBeTruthy();
    expect(screen.getByText('Upload files')).toBeTruthy();
    expect(container.querySelector('input[type="file"]')).toHaveAttribute('multiple');
  });

  it('hides the upload button when a single file already exists', () => {
    const t_i18n = vi.fn((content: string) => `translated:${content}`);
    renderFilesField({}, {
      values: { attachments: [{ name: 'report.pdf', data: 'encoded' }] },
      t_i18n,
    });

    expect(screen.queryByRole('button', { name: 'Upload' })).toBeNull();
    expect(screen.getByText('report.pdf')).toBeTruthy();
    // t_i18n is used for the chip's translated delete label, not the (absent) upload button.
    expect(t_i18n).toHaveBeenCalledWith('Remove');
  });

  it('keeps the upload button visible in multi-file mode with existing files', () => {
    renderFilesField({ multiple: true }, {
      values: { attachments: [{ name: 'report.pdf', data: 'encoded' }] },
    });

    expect(screen.getByRole('button', { name: 'Upload' })).toBeTruthy();
    expect(screen.getByText('Upload files')).toBeTruthy();
  });

  it('renders existing files as removable chips and calls setFieldValue with the fully-qualified prefixed path on removal', async () => {
    const setFieldValue = vi.fn();
    const values = { metadata: { attachments: [{ name: 'report.pdf', data: 'encoded' }] } };
    const { user } = renderFilesField({}, {
      values,
      fieldPrefix: 'metadata',
      setFieldValue,
      getNestedValue: (object, path) => path.split('.').reduce<unknown>((current, key) => {
        if (current && typeof current === 'object' && key in current) {
          return (current as Record<string, unknown>)[key];
        }
        return undefined;
      }, object),
    });

    expect(screen.getByText('report.pdf')).toBeTruthy();
    const deleteIcon = screen.getByRole('button', { name: 'Remove report.pdf' });
    expect(deleteIcon).toBeTruthy();

    await user.click(deleteIcon);

    // The renderer always calls back with the fully-qualified `fieldPrefix.field.name` path (matching
    // the Formik <Field> name); it is FormFieldRenderer's `setFieldValue` wrapper that is responsible
    // for reconciling that with a prefixing setter, not this renderer.
    expect(setFieldValue).toHaveBeenCalledWith('metadata.attachments', []);
  });

  it('uses singular and plural upload labels with the defensive translation fallback', () => {
    renderFilesField();
    expect(screen.getByText('Upload file')).toBeTruthy();
    cleanup();

    renderFilesField({ multiple: true });
    expect(screen.getByText('Upload files')).toBeTruthy();
    cleanup();

    const t_i18n = vi.fn((content: string) => `translated:${content}`);
    renderFilesField({ multiple: true }, { t_i18n });

    expect(screen.getByRole('button', { name: 'translated:Upload' })).toBeTruthy();
    expect(screen.getByText('translated:Upload files')).toBeTruthy();
    expect(t_i18n).toHaveBeenCalledWith('Upload');
    expect(t_i18n).toHaveBeenCalledWith('Upload files');
  });

  it('uses the supplied translation for the singular upload label', () => {
    const t_i18n = vi.fn((content: string) => `translated:${content}`);
    renderFilesField({}, { t_i18n });

    expect(screen.getByRole('button', { name: 'translated:Upload' })).toBeTruthy();
    expect(screen.getByText('translated:Upload file')).toBeTruthy();
    expect(t_i18n).toHaveBeenCalledWith('Upload');
    expect(t_i18n).toHaveBeenCalledWith('Upload file');
  });
});
