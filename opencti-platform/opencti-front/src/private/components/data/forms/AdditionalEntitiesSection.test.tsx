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
});
