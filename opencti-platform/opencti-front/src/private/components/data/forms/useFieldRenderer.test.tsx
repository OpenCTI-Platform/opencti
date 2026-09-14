import { cleanup, fireEvent, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import testRender, { testRenderHook } from '../../../../utils/tests/test-render';
import type { EntityTypeOption, FormBuilderData, FormFieldAttribute } from './Form.d';
import useFieldRenderer from './useFieldRenderer';

const entityTypes: EntityTypeOption[] = [
  {
    value: 'Report',
    label: 'Report',
    attributes: [
      { value: 'name', name: 'name', label: 'Name', type: 'string' },
      { value: 'description', name: 'description', label: 'Description', type: 'text' },
      {
        value: 'status',
        name: 'status',
        label: 'Status',
        type: 'string',
        defaultValues: [{ id: 'open', name: 'Open' }, { id: 'closed', name: 'Closed' }],
      },
      { value: 'tags', name: 'tags', label: 'Tags', type: 'string', multiple: true },
    ],
  },
  {
    value: 'Indicator',
    label: 'Indicator',
    attributes: [
      { value: 'pattern', name: 'pattern', label: 'Pattern', type: 'string' },
      { value: 'description', name: 'description', label: 'Description', type: 'text' },
    ],
  },
];

const createFormData = (overrides: Partial<FormBuilderData> = {}): FormBuilderData => ({
  name: 'Test form',
  description: '',
  mainEntityType: 'Report',
  includeInContainer: false,
  isDraftByDefault: false,
  allowDraftOverride: true,
  mainEntityMultiple: false,
  mainEntityFieldMode: 'multiple',
  additionalEntities: [],
  fields: [],
  relationships: [],
  active: true,
  ...overrides,
});

const createField = (overrides: Partial<FormFieldAttribute> = {}): FormFieldAttribute => ({
  id: 'field-1',
  name: 'field',
  label: 'Field',
  type: 'text',
  required: false,
  attributeMapping: {
    entity: 'main_entity',
    attributeName: 'name',
  },
  ...overrides,
});

const renderField = (
  field: FormFieldAttribute,
  formData: FormBuilderData = createFormData({ fields: [field] }),
  overrides: Partial<Parameters<typeof useFieldRenderer>[0]> = {},
) => {
  const params: Parameters<typeof useFieldRenderer>[0] = {
    formData,
    entityTypes,
    handleFieldChange: vi.fn(),
    renameField: vi.fn(),
    handleMoveFieldUp: vi.fn(),
    handleMoveFieldDown: vi.fn(),
    handleRemoveField: vi.fn(),
    ...overrides,
  };
  const { hook } = testRenderHook(() => useFieldRenderer(params));
  const renderedField = hook.result.current(field, 0, field.attributeMapping.entity === 'main_entity' ? 'Report' : 'Indicator', [field]);
  testRender(renderedField);
  return params;
};

const openAttributeMapping = () => {
  fireEvent.click(screen.getAllByRole('combobox')[0]);
};

describe('useFieldRenderer', () => {
  it('renders entity attributes and all special attribute options', () => {
    const field = createField({ attributeMapping: { entity: 'main_entity', attributeName: '' } });
    renderField(field);

    openAttributeMapping();

    expect(screen.getByRole('option', { name: 'Name' })).toBeInTheDocument();
    expect(screen.getByRole('option', { name: 'Created By' })).toBeInTheDocument();
    expect(screen.getByRole('option', { name: 'Marking Definitions' })).toBeInTheDocument();
    expect(screen.getByRole('option', { name: 'Labels' })).toBeInTheDocument();
    expect(screen.getByRole('option', { name: 'External References' })).toBeInTheDocument();
    expect(screen.getByRole('option', { name: 'Files' })).toBeInTheDocument();
    expect(screen.getByRole('option', { name: 'Main observable type' })).toBeInTheDocument();
  });

  it('updates mapping, label, name, and vocabulary field type when an attribute is selected', () => {
    const handleFieldChange = vi.fn();
    const field = createField({ attributeMapping: { entity: 'main_entity', attributeName: '' }, type: '' });
    renderField(field, createFormData({ fields: [field] }), { handleFieldChange });

    openAttributeMapping();
    fireEvent.click(screen.getByRole('option', { name: 'Status' }));

    expect(handleFieldChange).toHaveBeenCalledWith('fields.0.attributeMapping.attributeName', 'status');
    expect(handleFieldChange).toHaveBeenCalledWith('fields.0.label', 'Status');
    expect(handleFieldChange).toHaveBeenCalledWith('fields.0.name', 'status');
    expect(handleFieldChange).toHaveBeenCalledWith('fields.0.type', 'select');
  });

  it('disables move controls at the entity boundaries and calls move handlers otherwise', () => {
    const firstField = createField({ id: 'field-1' });
    const secondField = createField({
      id: 'field-2',
      name: 'description',
      label: 'Description',
      attributeMapping: { entity: 'main_entity', attributeName: 'description' },
    });
    const handleMoveFieldUp = vi.fn();
    const handleMoveFieldDown = vi.fn();
    const formData = createFormData({ fields: [firstField, secondField] });
    const params: Parameters<typeof useFieldRenderer>[0] = {
      formData,
      entityTypes,
      handleFieldChange: vi.fn(),
      renameField: vi.fn(),
      handleMoveFieldUp,
      handleMoveFieldDown,
      handleRemoveField: vi.fn(),
    };
    const { hook } = testRenderHook(() => useFieldRenderer(params));
    testRender(hook.result.current(firstField, 0, 'Report', [firstField, secondField]));
    testRender(hook.result.current(secondField, 1, 'Report', [firstField, secondField]));

    const moveUpButtons = screen.getAllByRole('button', { name: 'Move up' });
    const moveDownButtons = screen.getAllByRole('button', { name: 'Move down' });
    expect(moveUpButtons[0]).toBeDisabled();
    expect(moveDownButtons[1]).toBeDisabled();

    fireEvent.click(moveDownButtons[0]);
    fireEvent.click(moveUpButtons[1]);

    expect(handleMoveFieldDown).toHaveBeenCalledWith('main_entity', 'field-1');
    expect(handleMoveFieldUp).toHaveBeenCalledWith('main_entity', 'field-2');
  });

  it('deletes optional fields and hides delete for mandatory fields outside parsed mode', () => {
    const handleRemoveField = vi.fn();
    const optionalField = createField();
    renderField(optionalField, createFormData({ fields: [optionalField] }), { handleRemoveField });
    fireEvent.click(screen.getByRole('button', { name: 'Delete' }));
    expect(handleRemoveField).toHaveBeenCalledWith('field-1');

    cleanup();
    const mandatoryField = createField({ isMandatory: true });
    renderField(mandatoryField);
    expect(screen.queryByRole('button', { name: 'Delete' })).not.toBeInTheDocument();
  });

  it('filters the mapped attribute in parsed mode for main and additional entities', () => {
    const mainField = createField({ attributeMapping: { entity: 'main_entity', attributeName: 'name' } });
    renderField(
      mainField,
      createFormData({
        mainEntityFieldMode: 'parsed',
        mainEntityParseFieldMapping: 'status',
        fields: [mainField],
      }),
    );
    openAttributeMapping();
    expect(screen.queryByRole('option', { name: 'Status' })).not.toBeInTheDocument();

    const additionalField = createField({
      id: 'field-2',
      attributeMapping: { entity: 'entity-1', attributeName: 'pattern' },
    });
    renderField(
      additionalField,
      createFormData({
        additionalEntities: [{
          id: 'entity-1',
          entityType: 'Indicator',
          label: 'Indicators',
          multiple: false,
          fieldMode: 'parsed',
          parseFieldMapping: 'description',
        }],
        fields: [additionalField],
      }),
    );
    openAttributeMapping();
    expect(screen.queryByRole('option', { name: 'Description' })).not.toBeInTheDocument();
  });

  it('renders vocabulary options read-only and custom option controls without vocabulary', () => {
    const vocabularyField = createField({
      type: 'select',
      attributeMapping: { entity: 'main_entity', attributeName: 'status' },
    });
    renderField(vocabularyField);
    expect(screen.getByText('Options (from vocabulary)')).toBeInTheDocument();
    expect(screen.getByText('• Open')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Add option' })).not.toBeInTheDocument();

    cleanup();
    const customField = createField({
      type: 'select',
      attributeMapping: { entity: 'main_entity', attributeName: 'name' },
      options: [{ label: 'First', value: 'first' }],
    });
    renderField(customField);
    expect(screen.getByText('Options')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Add option' })).toBeInTheDocument();
    expect(screen.getAllByRole('textbox', { name: 'Label' })).toHaveLength(1);
  });

  it('renders default value controls only for applicable field types', () => {
    const textField = createField({ type: 'text' });
    renderField(textField);
    expect(screen.getByRole('textbox', { name: 'Default value' })).toBeInTheDocument();

    cleanup();
    const checkboxField = createField({ type: 'checkbox' });
    renderField(checkboxField);
    expect(screen.queryByRole('textbox', { name: 'Default value' })).not.toBeInTheDocument();
    expect(screen.getAllByRole('combobox').length).toBeGreaterThan(0);
  });
});
