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
      { value: 'priority', name: 'priority', label: 'Priority', type: 'string' },
      { value: 'confidence', name: 'confidence', label: 'Confidence', type: 'numeric' },
      { value: 'created', name: 'created', label: 'Created', type: 'date' },
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

  it('auto-assigns openvocab for a whitelisted attribute and shows it selected and locked', () => {
    const handleFieldChange = vi.fn();
    const field = createField({ attributeMapping: { entity: 'main_entity', attributeName: '' }, type: '' });
    renderField(field, createFormData({ fields: [field] }), { handleFieldChange });

    openAttributeMapping();
    fireEvent.click(screen.getByRole('option', { name: 'Priority' }));

    expect(handleFieldChange).toHaveBeenCalledWith('fields.0.type', 'openvocab');

    cleanup();
    const vocabField = createField({
      type: 'openvocab',
      attributeMapping: { entity: 'main_entity', attributeName: 'priority' },
    });
    renderField(vocabField);
    const fieldTypeSelect = screen.getAllByRole('combobox')[1];
    expect(fieldTypeSelect).toHaveTextContent('Open Vocabulary');
    expect(fieldTypeSelect).not.toHaveAttribute('disabled');
    fireEvent.click(fieldTypeSelect);
    expect(screen.getAllByRole('option')).toHaveLength(1);
  });

  it('locks the field type to Number/Date & Time for numeric and date attributes', () => {
    const handleFieldChange = vi.fn();
    const field = createField({ attributeMapping: { entity: 'main_entity', attributeName: '' }, type: '' });
    renderField(field, createFormData({ fields: [field] }), { handleFieldChange });

    openAttributeMapping();
    fireEvent.click(screen.getByRole('option', { name: 'Confidence' }));
    expect(handleFieldChange).toHaveBeenCalledWith('fields.0.type', 'number');

    cleanup();
    const numberField = createField({
      type: 'number',
      attributeMapping: { entity: 'main_entity', attributeName: 'confidence' },
    });
    renderField(numberField);
    const numberFieldTypeSelect = screen.getAllByRole('combobox')[1];
    expect(numberFieldTypeSelect).toHaveTextContent('Number');
    expect(numberFieldTypeSelect).not.toHaveAttribute('disabled');
    fireEvent.click(numberFieldTypeSelect);
    expect(screen.getAllByRole('option')).toHaveLength(1);

    cleanup();
    const dateField = createField({
      type: 'datetime',
      attributeMapping: { entity: 'main_entity', attributeName: 'created' },
    });
    renderField(dateField);
    const dateFieldTypeSelect = screen.getAllByRole('combobox')[1];
    expect(dateFieldTypeSelect).toHaveTextContent('Date & Time');
    expect(dateFieldTypeSelect).not.toHaveAttribute('disabled');
    fireEvent.click(dateFieldTypeSelect);
    expect(screen.getAllByRole('option')).toHaveLength(1);
  });

  it('ignores a spurious empty onValueChange from the Field Type select instead of resetting the type', () => {
    // Regression test for a real bug: the underlying Select can fire onValueChange('') when its
    // value and options list change together in the same render (e.g. right after the attribute
    // select auto-assigns a forced type), which used to silently wipe out the just-set type.
    const handleFieldChange = vi.fn();
    const field = createField({
      type: 'openvocab',
      attributeMapping: { entity: 'main_entity', attributeName: 'priority' },
    });
    renderField(field, createFormData({ fields: [field] }), { handleFieldChange });

    const fieldTypeSelect = screen.getAllByRole('combobox')[1];
    const fiberKey = Object.keys(fieldTypeSelect).find((key) => key.startsWith('__reactFiber$'));
    expect(fiberKey).toBeDefined();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let fiber: any = (fieldTypeSelect as any)[fiberKey as string];
    let onValueChange: ((value: string) => void) | undefined;
    for (let i = 0; i < 20 && fiber && !onValueChange; i += 1) {
      onValueChange = fiber.memoizedProps?.onValueChange;
      fiber = fiber.return;
    }
    expect(onValueChange).toBeInstanceOf(Function);

    (onValueChange as (value: string) => void)('');

    expect(handleFieldChange).not.toHaveBeenCalledWith('fields.0.type', '');
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

  it('generates a name from the field label when it is edited', () => {
    const renameField = vi.fn();
    const field = createField();
    renderField(field, createFormData({ fields: [field] }), { renameField });

    fireEvent.change(screen.getByRole('textbox', { name: 'Field Label' }), { target: { value: 'New Label' } });

    expect(renameField).toHaveBeenCalledWith('field-1', 'New Label');
  });

  it('adds, edits, and removes custom options for a select field without vocabulary', () => {
    const handleFieldChange = vi.fn();
    const field = createField({
      type: 'select',
      attributeMapping: { entity: 'main_entity', attributeName: 'name' },
      options: [{ label: 'First', value: 'first' }],
    });
    renderField(field, createFormData({ fields: [field] }), { handleFieldChange });

    fireEvent.change(screen.getByRole('textbox', { name: 'Label' }), { target: { value: 'Renamed' } });
    expect(handleFieldChange).toHaveBeenCalledWith('fields.0.options', [{ label: 'Renamed', value: 'first' }]);

    fireEvent.change(screen.getByRole('textbox', { name: 'Value' }), { target: { value: 'renamed-value' } });
    expect(handleFieldChange).toHaveBeenCalledWith('fields.0.options', [{ label: 'First', value: 'renamed-value' }]);

    fireEvent.click(screen.getByRole('button', { name: 'Add option' }));
    expect(handleFieldChange).toHaveBeenCalledWith('fields.0.options', [
      { label: 'First', value: 'first' },
      { label: '', value: '' },
    ]);

    const deleteButtons = screen.getAllByRole('button', { name: 'Delete' });
    fireEvent.click(deleteButtons[deleteButtons.length - 1]);
    expect(handleFieldChange).toHaveBeenCalledWith('fields.0.options', []);
  });

  it('sets a number default value and coerces empty input to null', () => {
    const handleFieldChange = vi.fn();
    const numberField = createField({ type: 'number' });
    renderField(numberField, createFormData({ fields: [numberField] }), { handleFieldChange });
    fireEvent.change(screen.getByRole('spinbutton', { name: 'Default value' }), { target: { value: '42' } });
    expect(handleFieldChange).toHaveBeenCalledWith('fields.0.defaultValue', 42);
  });

  it('sets a text default value and shows the date helper text for date fields', () => {
    const handleFieldChange = vi.fn();
    const textField = createField({ type: 'text' });
    renderField(textField, createFormData({ fields: [textField] }), { handleFieldChange });
    fireEvent.change(screen.getByRole('textbox', { name: 'Default value' }), { target: { value: 'hello' } });
    expect(handleFieldChange).toHaveBeenCalledWith('fields.0.defaultValue', 'hello');

    cleanup();
    const dateField = createField({ type: 'date' });
    renderField(dateField);
    expect(screen.getByText('Enter date in ISO format (e.g., 2024-01-01 or 2024-01-01T10:00:00.000Z)')).toBeInTheDocument();
  });

  it('sets the checkbox/toggle default value through the select options', () => {
    const handleFieldChange = vi.fn();
    const field = createField({ type: 'checkbox' });
    renderField(field, createFormData({ fields: [field] }), { handleFieldChange });

    const selects = screen.getAllByRole('combobox');
    const defaultValueSelect = selects.find((select) => select.textContent === 'No default');
    fireEvent.click(defaultValueSelect as HTMLElement);
    fireEvent.click(screen.getByRole('option', { name: 'Default checked (true)' }));
    expect(handleFieldChange).toHaveBeenCalledWith('fields.0.defaultValue', true);
  });

  it('updates the field width', () => {
    const handleFieldChange = vi.fn();
    const field = createField();
    renderField(field, createFormData({ fields: [field] }), { handleFieldChange });

    const selects = screen.getAllByRole('combobox');
    const widthSelect = selects.find((select) => select.textContent === 'Full width');
    fireEvent.click(widthSelect as HTMLElement);
    fireEvent.click(screen.getByRole('option', { name: 'Half width' }));

    expect(handleFieldChange).toHaveBeenCalledWith('fields.0.width', 'half');
  });

  it('toggles allow-multiple-files for files fields', () => {
    const handleFieldChange = vi.fn();
    const field = createField({ type: 'files' });
    renderField(field, createFormData({ fields: [field] }), { handleFieldChange });

    fireEvent.click(screen.getByRole('checkbox', { name: 'Allow multiple files' }));

    expect(handleFieldChange).toHaveBeenCalledWith('fields.0.multiple', true);
  });

  it('does not show the allow-multiple-files toggle for non-files fields', () => {
    const field = createField({ type: 'text' });
    renderField(field);

    expect(screen.queryByRole('checkbox', { name: 'Allow multiple files' })).not.toBeInTheDocument();
  });

  it('toggles read-only and required switches, disabling required for mandatory fields', () => {
    const handleFieldChange = vi.fn();
    const field = createField();
    renderField(field, createFormData({ fields: [field] }), { handleFieldChange });

    fireEvent.click(screen.getByRole('checkbox', { name: 'Not editable by user' }));
    expect(handleFieldChange).toHaveBeenCalledWith('fields.0.isReadOnly', true);

    fireEvent.click(screen.getByRole('checkbox', { name: 'Required' }));
    expect(handleFieldChange).toHaveBeenCalledWith('fields.0.required', true);

    cleanup();
    const mandatoryField = createField({ isMandatory: true });
    renderField(mandatoryField);
    expect(screen.getByRole('checkbox', { name: 'Required' })).toBeDisabled();
  });
});
