import { describe, expect, it, vi } from 'vitest';
import { fireEvent, screen } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import MainEntitySection, { type MainEntitySectionProps } from './MainEntitySection';
import type { FormBuilderData, FormFieldAttribute } from './Form.d';

const baseFormData: FormBuilderData = {
  name: 'Test form',
  description: '',
  mainEntityType: 'Report',
  includeInContainer: false,
  isDraftByDefault: false,
  allowDraftOverride: true,
  draftDefaults: {
    name: { isEditable: false, isRequired: false, defaultValue: '' },
    description: { isEditable: false, isRequired: false, defaultValue: '' },
    objectAssignee: { isEditable: false, isRequired: false, defaults: [] },
    objectParticipant: { isEditable: false, isRequired: false, defaults: [] },
    author: { type: 'none', isEditable: false, isRequired: false },
    authorizedMembers: { enabled: false, isEditable: false, isRequired: false, defaults: [] },
  },
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

const renderSection = (overrides: Partial<MainEntitySectionProps> = {}) => {
  const props: MainEntitySectionProps = {
    formData: baseFormData,
    handleFieldChange: vi.fn(),
    updateFormData: vi.fn(),
    entityTypes: [
      { value: 'Report', label: 'Report' },
      { value: 'Indicator', label: 'Indicator' },
    ],
    handleMainEntityTypeChange: vi.fn(),
    isContainer: false,
    entitySettings: { edges: [] },
    fieldsByEntity: { main_entity: [] },
    renderField: vi.fn(),
    handleAddField: vi.fn(),
    tabPanelClassName: 'tab-panel',
    alertClassName: 'alert',
    addButtonClassName: 'add-button',
    ...overrides,
  };

  testRender(<MainEntitySection {...props} />);
  return props;
};

describe('MainEntitySection', () => {
  it('renders the main entity type select with the current value', () => {
    renderSection();

    expect(screen.getByRole('combobox')).toHaveTextContent('Report');
  });

  it('calls the type-change handler with the selected value', () => {
    const handleMainEntityTypeChange = vi.fn();
    renderSection({ handleMainEntityTypeChange });

    fireEvent.click(screen.getByRole('combobox'));
    fireEvent.click(screen.getByRole('option', { name: 'Indicator' }));

    expect(handleMainEntityTypeChange).toHaveBeenCalledWith('Indicator');
  });

  it('reflects and updates the entity lookup toggle', () => {
    const handleFieldChange = vi.fn();
    renderSection({
      formData: { ...baseFormData, mainEntityLookup: true },
      handleFieldChange,
    });

    const lookupToggle = screen.getByRole('checkbox', { name: 'Entity lookup (select existing entities)' });
    expect(lookupToggle).toBeChecked();

    fireEvent.click(lookupToggle);

    expect(handleFieldChange).toHaveBeenCalledWith('mainEntityLookup', false);
  });

  it('renders lookup-only and container-only toggles under their respective conditions', () => {
    renderSection({
      formData: { ...baseFormData, mainEntityLookup: true },
      isContainer: true,
    });

    expect(screen.getByRole('checkbox', { name: 'Disable on-the-fly entity creation' })).toBeInTheDocument();
    expect(screen.getByRole('checkbox', { name: 'Include entities in container' })).toBeInTheDocument();
  });

  it('renders the lookup information alert', () => {
    renderSection({ formData: { ...baseFormData, mainEntityLookup: true } });

    expect(screen.getByText('Entity lookup enabled. Users will select existing entities of this type.')).toBeInTheDocument();
  });

  it('renders the parsed-mode information alert', () => {
    renderSection({
      formData: {
        ...baseFormData,
        mainEntityMultiple: true,
        mainEntityFieldMode: 'parsed',
      },
    });

    expect(screen.getByText('Parsed mode enabled. Users can enter multiple values in a single field. Additional fields can be defined that will apply to all created entities.')).toBeInTheDocument();
  });

  it('renders main entity fields through renderField', () => {
    const field: FormFieldAttribute = {
      id: 'field-1',
      name: 'name',
      label: 'Name',
      type: 'text',
      required: false,
      attributeMapping: {
        entity: 'main_entity',
        attributeName: 'name',
      },
    };
    const renderField = vi.fn();
    renderSection({
      fieldsByEntity: { main_entity: [field] },
      renderField,
    });

    expect(renderField).toHaveBeenCalledWith(field, 0, 'Report', [field]);
  });
});
