import { describe, expect, it, vi } from 'vitest';
import { fireEvent, screen } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import AdditionalEntitiesSection, { type AdditionalEntitiesSectionProps } from './AdditionalEntitiesSection';
import type { FormBuilderData, FormFieldAttribute } from './Form.d';

const baseFormData: FormBuilderData = {
  name: 'Test form',
  description: '',
  mainEntityType: 'Report',
  includeInContainer: false,
  isDraftByDefault: false,
  allowDraftOverride: true,
  mainEntityMultiple: false,
  mainEntityLookup: false,
  mainEntityFieldMode: 'multiple',
  mainEntityParseField: 'text',
  mainEntityParseMode: 'comma',
  additionalEntities: [],
  fields: [],
  relationships: [],
  active: true,
};

const baseEntity = {
  id: 'entity-1',
  entityType: 'Indicator',
  label: 'Indicators',
  multiple: false,
  lookup: false,
  fieldMode: 'multiple' as const,
};

const renderSection = (overrides: Partial<AdditionalEntitiesSectionProps> = {}) => {
  const props: AdditionalEntitiesSectionProps = {
    formData: {
      ...baseFormData,
      additionalEntities: [baseEntity],
    },
    handleFieldChange: vi.fn(),
    toggleParsedMode: vi.fn(),
    updateFormData: vi.fn(),
    entityTypes: [
      { value: 'Indicator', label: 'Indicator' },
      { value: 'Report', label: 'Report' },
    ],
    fieldsByEntity: { [baseEntity.id]: [] },
    handleRemoveAdditionalEntity: vi.fn(),
    entitySettings: { edges: [] },
    renderField: vi.fn(),
    handleAddField: vi.fn(),
    handleAddAdditionalEntity: vi.fn(),
    ...overrides,
  };

  testRender(<AdditionalEntitiesSection {...props} />);
  return props;
};

describe('AdditionalEntitiesSection', () => {
  it('renders one entity block per additional entity', () => {
    renderSection({
      formData: {
        ...baseFormData,
        additionalEntities: [
          baseEntity,
          { ...baseEntity, id: 'entity-2', label: 'Malware' },
        ],
      },
    });

    expect(screen.getByText('Indicators')).toBeInTheDocument();
    expect(screen.getByText('Malware')).toBeInTheDocument();
  });

  it('calls handleAddAdditionalEntity when the add button is clicked', () => {
    const handleAddAdditionalEntity = vi.fn();
    renderSection({ handleAddAdditionalEntity });

    fireEvent.click(screen.getByRole('button', { name: 'Add additional entity' }));

    expect(handleAddAdditionalEntity).toHaveBeenCalledOnce();
  });

  it('handles entity type changes and updates mandatory fields', () => {
    const handleFieldChange = vi.fn();
    const updateFormData = vi.fn();
    renderSection({ handleFieldChange, updateFormData });

    fireEvent.click(screen.getByRole('combobox'));
    fireEvent.click(screen.getByRole('option', { name: 'Report' }));

    expect(handleFieldChange).toHaveBeenCalledWith('additionalEntities.0.entityType', 'Report');
    expect(updateFormData).toHaveBeenCalledOnce();
  });

  it('only renders the disable-creation toggle in lookup mode', () => {
    renderSection({
      formData: {
        ...baseFormData,
        additionalEntities: [{ ...baseEntity, lookup: true }],
      },
    });

    expect(screen.getByRole('checkbox', { name: 'Disable on-the-fly entity creation' })).toBeInTheDocument();
  });

  it('does not render the disable-creation toggle outside lookup mode', () => {
    renderSection();

    expect(screen.queryByRole('checkbox', { name: 'Disable on-the-fly entity creation' })).not.toBeInTheDocument();
  });

  it('renders the minimum amount field for multiple entities', () => {
    renderSection({
      formData: {
        ...baseFormData,
        additionalEntities: [{ ...baseEntity, multiple: true }],
      },
    });

    expect(screen.getByLabelText('Minimum amount (0 for optional)')).toBeInTheDocument();
    expect(screen.queryByRole('checkbox', { name: 'Required' })).not.toBeInTheDocument();
  });

  it('renders the required toggle for non-multiple entities', () => {
    renderSection();

    expect(screen.getByRole('checkbox', { name: 'Required' })).toBeInTheDocument();
    expect(screen.queryByLabelText('Minimum amount (0 for optional)')).not.toBeInTheDocument();
  });

  it('renders each field through renderField when the entity is not in lookup mode', () => {
    const field: FormFieldAttribute = {
      id: 'field-1',
      name: 'name',
      label: 'Name',
      type: 'text',
      required: false,
      attributeMapping: {
        entity: baseEntity.id,
        attributeName: 'name',
      },
    };
    const renderField = vi.fn();
    renderSection({
      fieldsByEntity: { [baseEntity.id]: [field] },
      renderField,
    });

    expect(renderField).toHaveBeenCalledWith(field, 0, 'Indicator', [field]);
  });

  it('updates the entity label', () => {
    const handleFieldChange = vi.fn();
    renderSection({ handleFieldChange });

    fireEvent.change(screen.getByLabelText('Label for entities'), { target: { value: 'My Indicators' } });

    expect(handleFieldChange).toHaveBeenCalledWith('additionalEntities.0.label', 'My Indicators');
  });

  it('toggles the entity lookup switch', () => {
    const handleFieldChange = vi.fn();
    renderSection({ handleFieldChange });

    fireEvent.click(screen.getByRole('checkbox', { name: 'Entity lookup (select existing entities)' }));

    expect(handleFieldChange).toHaveBeenCalledWith('additionalEntities.0.lookup', true);
  });

  it('toggles the disable-creation switch in lookup mode', () => {
    const handleFieldChange = vi.fn();
    renderSection({
      handleFieldChange,
      formData: {
        ...baseFormData,
        additionalEntities: [{ ...baseEntity, lookup: true }],
      },
    });

    fireEvent.click(screen.getByRole('checkbox', { name: 'Disable on-the-fly entity creation' }));

    expect(handleFieldChange).toHaveBeenCalledWith('additionalEntities.0.disableCreation', true);
  });

  it('toggles the multiple-instances switch', () => {
    const handleFieldChange = vi.fn();
    renderSection({ handleFieldChange });

    fireEvent.click(screen.getByRole('checkbox', { name: 'Allow multiple instances' }));

    expect(handleFieldChange).toHaveBeenCalledWith('additionalEntities.0.multiple', true);
  });

  it('updates the minimum amount for multiple entities', () => {
    const handleFieldChange = vi.fn();
    renderSection({
      handleFieldChange,
      formData: {
        ...baseFormData,
        additionalEntities: [{ ...baseEntity, multiple: true }],
      },
    });

    fireEvent.change(screen.getByLabelText('Minimum amount (0 for optional)'), { target: { value: '3' } });

    expect(handleFieldChange).toHaveBeenCalledWith('additionalEntities.0.minAmount', 3);
  });

  it('toggles the required switch for non-multiple entities without default values', () => {
    const handleFieldChange = vi.fn();
    renderSection({ handleFieldChange });

    const requiredSwitch = screen.getByRole('checkbox', { name: 'Required' });
    expect(requiredSwitch).not.toBeDisabled();

    fireEvent.click(requiredSwitch);

    expect(handleFieldChange).toHaveBeenCalledWith('additionalEntities.0.required', true);
  });

  it('disables and auto-labels the required switch when a field has a default value', () => {
    const field: FormFieldAttribute = {
      id: 'field-1',
      name: 'name',
      label: 'Name',
      type: 'text',
      required: false,
      defaultValue: 'Some default',
      attributeMapping: { entity: baseEntity.id, attributeName: 'name' },
    };
    renderSection({ fieldsByEntity: { [baseEntity.id]: [field] } });

    const requiredSwitch = screen.getByRole('checkbox', { name: 'Required (auto-set due to default values)' });
    expect(requiredSwitch).toBeDisabled();
  });

  it('renders the multiple-mode select for multiple non-lookup entities and toggles the field mode', () => {
    const toggleParsedMode = vi.fn();
    renderSection({
      toggleParsedMode,
      formData: {
        ...baseFormData,
        additionalEntities: [{ ...baseEntity, multiple: true, fieldMode: 'multiple' }],
      },
    });

    const selects = screen.getAllByRole('combobox');
    fireEvent.click(selects[1]);
    fireEvent.click(screen.getByRole('option', { name: 'Parsed values' }));

    expect(toggleParsedMode).toHaveBeenCalledWith('entity-1', 'parsed');
  });

  it('renders parse-field, parse-mode selects and updates the parse field type', () => {
    const handleFieldChange = vi.fn();
    renderSection({
      handleFieldChange,
      formData: {
        ...baseFormData,
        additionalEntities: [{
          ...baseEntity, multiple: true, fieldMode: 'parsed', parseField: 'text', parseMode: 'comma',
        }],
      },
    });

    const selects = screen.getAllByRole('combobox');
    // 0: entity type, 1: multiple mode, 2: parse field type, 3: parse mode, 4: parse field mapping
    fireEvent.click(selects[2]);
    fireEvent.click(screen.getByRole('option', { name: 'Text Area' }));

    expect(handleFieldChange).toHaveBeenCalledWith('additionalEntities.0.parseField', 'textarea');
  });

  it('only shows the one-per-line parse mode option for textarea parse fields', () => {
    renderSection({
      formData: {
        ...baseFormData,
        additionalEntities: [{
          ...baseEntity, multiple: true, fieldMode: 'parsed', parseField: 'text', parseMode: 'comma',
        }],
      },
    });

    const selects = screen.getAllByRole('combobox');
    fireEvent.click(selects[3]);
    expect(screen.queryByRole('option', { name: 'One per line' })).not.toBeInTheDocument();
  });

  it('updates the parse mode selection', () => {
    const handleFieldChange = vi.fn();
    renderSection({
      handleFieldChange,
      formData: {
        ...baseFormData,
        additionalEntities: [{
          ...baseEntity, multiple: true, fieldMode: 'parsed', parseField: 'textarea', parseMode: 'comma',
        }],
      },
    });

    const selects = screen.getAllByRole('combobox');
    fireEvent.click(selects[3]);
    fireEvent.click(screen.getByRole('option', { name: 'One per line' }));

    expect(handleFieldChange).toHaveBeenCalledWith('additionalEntities.0.parseMode', 'line');
  });

  it('maps parsed values to an available attribute and removes superseded fields', () => {
    const updateFormData = vi.fn();
    renderSection({
      updateFormData,
      formData: {
        ...baseFormData,
        additionalEntities: [{
          ...baseEntity, multiple: true, fieldMode: 'parsed', parseField: 'text', parseMode: 'comma',
        }],
      },
      entitySettings: {
        edges: [{
          node: {
            target_type: 'Indicator',
            attributesDefinitions: [
              { type: 'string', name: 'description', label: 'Description', mandatory: false, upsert: true },
              { type: 'string', name: 'not-upsert', label: 'Not upsert', mandatory: false, upsert: false },
            ],
          },
        }],
      },
    });

    const selects = screen.getAllByRole('combobox');
    fireEvent.click(selects[4]);
    expect(screen.queryByRole('option', { name: 'Not upsert' })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('option', { name: 'Description' }));

    expect(updateFormData).toHaveBeenCalledOnce();
  });

  it('shows the STIX pattern auto-convert toggle only for Indicator entities in parsed mode', () => {
    const handleFieldChange = vi.fn();
    renderSection({
      handleFieldChange,
      formData: {
        ...baseFormData,
        additionalEntities: [{
          ...baseEntity, entityType: 'Indicator', multiple: true, fieldMode: 'parsed', parseField: 'text', parseMode: 'comma',
        }],
      },
    });

    const toggle = screen.getByRole('checkbox', { name: 'Automatically convert to STIX patterns' });
    fireEvent.click(toggle);

    expect(handleFieldChange).toHaveBeenCalledWith('additionalEntities.0.autoConvertToStixPattern', true);
  });

  it('does not show the STIX pattern auto-convert toggle for non-Indicator entities', () => {
    renderSection({
      formData: {
        ...baseFormData,
        additionalEntities: [{
          ...baseEntity, entityType: 'Malware', multiple: true, fieldMode: 'parsed', parseField: 'text', parseMode: 'comma',
        }],
      },
    });

    expect(screen.queryByRole('checkbox', { name: 'Automatically convert to STIX patterns' })).not.toBeInTheDocument();
  });

  it('renders additional fields for entities in parsed mode with a mapping set, excluding the mapped attribute', () => {
    const mappedField: FormFieldAttribute = {
      id: 'field-1',
      name: 'description',
      label: 'Description',
      type: 'text',
      required: false,
      attributeMapping: { entity: baseEntity.id, attributeName: 'description' },
    };
    const otherField: FormFieldAttribute = {
      id: 'field-2',
      name: 'confidence',
      label: 'Confidence',
      type: 'number',
      required: false,
      attributeMapping: { entity: baseEntity.id, attributeName: 'confidence' },
    };
    const renderField = vi.fn();
    renderSection({
      renderField,
      fieldsByEntity: { [baseEntity.id]: [mappedField, otherField] },
      formData: {
        ...baseFormData,
        additionalEntities: [{
          ...baseEntity, multiple: true, fieldMode: 'parsed', parseField: 'text', parseMode: 'comma', parseFieldMapping: 'description',
        }],
      },
    });

    expect(renderField).toHaveBeenCalledWith(otherField, 0, 'Indicator', [otherField]);
    expect(renderField).not.toHaveBeenCalledWith(mappedField, expect.anything(), expect.anything(), expect.anything());
  });

  it('calls handleAddField when the add field button is clicked', () => {
    const handleAddField = vi.fn();
    renderSection({ handleAddField });

    fireEvent.click(screen.getByRole('button', { name: 'Add field' }));

    expect(handleAddField).toHaveBeenCalledWith('entity-1', 'Indicator');
  });

  it('calls handleRemoveAdditionalEntity when the remove button is clicked', () => {
    const handleRemoveAdditionalEntity = vi.fn();
    renderSection({ handleRemoveAdditionalEntity });

    fireEvent.click(screen.getByRole('button', { name: 'Remove' }));

    expect(handleRemoveAdditionalEntity).toHaveBeenCalledWith('entity-1');
  });

  it('adds mandatory fields for the new entity type when switching entity type outside parsed mode', () => {
    const updateFormData = vi.fn();
    renderSection({
      updateFormData,
      entityTypes: [
        { value: 'Indicator', label: 'Indicator' },
        {
          value: 'Report',
          label: 'Report',
          attributes: [{ value: 'report_types', name: 'report_types', label: 'Report types', mandatory: true, type: 'string' }],
        },
      ],
    });

    fireEvent.click(screen.getByRole('combobox'));
    fireEvent.click(screen.getByRole('option', { name: 'Report' }));

    const updater = updateFormData.mock.calls[0][0];
    const prevState = {
      ...baseFormData,
      additionalEntities: [{ ...baseEntity, entityType: 'Report' }],
      fields: [{
        id: 'other-field', name: 'x', label: 'X', type: 'text', required: false,
        attributeMapping: { entity: 'other-entity', attributeName: 'x' },
      }],
    };

    const result = updater(prevState);

    expect(result.fields).toHaveLength(2);
    expect(result.fields[0]).toEqual(prevState.fields[0]);
    expect(result.fields[1]).toMatchObject({
      attributeMapping: { entity: 'entity-1', attributeName: 'report_types', mappingType: 'nested' },
    });
  });

  it('does not add mandatory fields when switching entity type while in parsed mode', () => {
    const updateFormData = vi.fn();
    renderSection({
      updateFormData,
      formData: {
        ...baseFormData,
        additionalEntities: [{
          ...baseEntity, multiple: true, fieldMode: 'parsed', parseField: 'text', parseMode: 'comma',
        }],
      },
      entityTypes: [
        { value: 'Indicator', label: 'Indicator' },
        {
          value: 'Report',
          label: 'Report',
          attributes: [{ value: 'report_types', name: 'report_types', label: 'Report types', mandatory: true, type: 'string' }],
        },
      ],
    });

    fireEvent.click(screen.getAllByRole('combobox')[0]);
    fireEvent.click(screen.getByRole('option', { name: 'Report' }));

    const updater = updateFormData.mock.calls[0][0];
    const prevState = {
      ...baseFormData,
      additionalEntities: [{
        ...baseEntity, multiple: true, fieldMode: 'parsed', entityType: 'Report',
      }],
      fields: [{
        id: 'own-field', name: 'name', label: 'Name', type: 'text', required: false,
        attributeMapping: { entity: 'entity-1', attributeName: 'name' },
      }],
    };

    const result = updater(prevState);

    expect(result.fields).toEqual([]);
  });

  it('updates the parse field mapping and prunes fields superseded by the new mapping', () => {
    const updateFormData = vi.fn();
    renderSection({
      updateFormData,
      formData: {
        ...baseFormData,
        additionalEntities: [{
          ...baseEntity, multiple: true, fieldMode: 'parsed', parseField: 'text', parseMode: 'comma', parseFieldMapping: 'description',
        }],
      },
      entitySettings: {
        edges: [{
          node: {
            target_type: 'Indicator',
            attributesDefinitions: [
              { type: 'string', name: 'description', label: 'Description', mandatory: false, upsert: true },
              { type: 'string', name: 'name', label: 'Name', mandatory: false, upsert: true },
            ],
          },
        }],
      },
    });

    fireEvent.click(screen.getAllByRole('combobox')[4]);
    fireEvent.click(screen.getByRole('option', { name: 'Name' }));

    const updater = updateFormData.mock.calls[0][0];
    const prevState = {
      ...baseFormData,
      additionalEntities: [{
        ...baseEntity, multiple: true, fieldMode: 'parsed', parseFieldMapping: 'description',
      }],
      fields: [
        {
          id: 'name-field', name: 'name', label: 'Name', type: 'text', required: false,
          attributeMapping: { entity: 'entity-1', attributeName: 'name' },
        },
      ],
    };

    const result = updater(prevState);

    expect(result.additionalEntities[0].parseFieldMapping).toBe('name');
    expect(result.fields).toEqual([]);
  });

  it('shows a default label based on entity position when no label is set', () => {
    renderSection({
      formData: {
        ...baseFormData,
        additionalEntities: [{ ...baseEntity, label: '' }],
      },
    });

    expect(screen.getByText('Additional Entity 1')).toBeInTheDocument();
  });
});
