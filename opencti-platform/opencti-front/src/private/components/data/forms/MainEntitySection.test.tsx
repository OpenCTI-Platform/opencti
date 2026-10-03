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
    toggleParsedMode: vi.fn(),
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

  it('toggles allow-multiple-instances of the main entity', () => {
    const handleFieldChange = vi.fn();
    renderSection({ handleFieldChange });

    fireEvent.click(screen.getByRole('checkbox', { name: 'Allow multiple instances of main entity' }));

    expect(handleFieldChange).toHaveBeenCalledWith('mainEntityMultiple', true);
  });

  it('calls handleAddField when Add field is clicked in the default fields view', () => {
    const handleAddField = vi.fn();
    renderSection({ handleAddField });

    fireEvent.click(screen.getByRole('button', { name: 'Add field' }));

    expect(handleAddField).toHaveBeenCalledWith('main_entity', 'Report');
  });

  it('switches the multiple mode via the Multiple Mode select', () => {
    const toggleParsedMode = vi.fn();
    renderSection({
      formData: { ...baseFormData, mainEntityMultiple: true },
      toggleParsedMode,
    });

    const multipleModeSelect = screen.getAllByRole('combobox').find((select) => select.textContent === 'Multiple fields') as HTMLElement;
    fireEvent.click(multipleModeSelect);
    fireEvent.click(screen.getByRole('option', { name: 'Parsed values' }));

    expect(toggleParsedMode).toHaveBeenCalledWith('main', 'parsed');
  });

  describe('parsed mode controls', () => {
    const parsedFormData: FormBuilderData = {
      ...baseFormData,
      mainEntityMultiple: true,
      mainEntityFieldMode: 'parsed',
      mainEntityParseField: 'textarea',
    };

    it('changes the parse field type and shows the one-per-line option only for textarea', () => {
      const handleFieldChange = vi.fn();
      renderSection({ formData: parsedFormData, handleFieldChange });

      const parseFieldSelect = screen.getAllByRole('combobox').find((select) => select.textContent === 'Text Area') as HTMLElement;
      fireEvent.click(parseFieldSelect);
      fireEvent.click(screen.getByRole('option', { name: 'Text' }));

      expect(handleFieldChange).toHaveBeenCalledWith('mainEntityParseField', 'text');

      const parseModeSelect = screen.getAllByRole('combobox').find((select) => select.textContent === 'Comma-separated') as HTMLElement;
      fireEvent.click(parseModeSelect);
      expect(screen.getByRole('option', { name: 'One per line' })).toBeInTheDocument();
    });

    it('does not show the one-per-line parse mode option for text parse field', () => {
      renderSection({ formData: { ...parsedFormData, mainEntityParseField: 'text' } });

      const parseModeSelect = screen.getAllByRole('combobox').find((select) => select.textContent === 'Comma-separated') as HTMLElement;
      fireEvent.click(parseModeSelect);
      expect(screen.queryByRole('option', { name: 'One per line' })).not.toBeInTheDocument();
    });

    it('updates mainEntityParseFieldMapping and prunes superseded fields via updateFormData', () => {
      const updateFormData = vi.fn();
      renderSection({
        formData: {
          ...parsedFormData,
          mainEntityType: 'Report',
        },
        entitySettings: {
          edges: [{
            node: {
              target_type: 'Report',
              attributesDefinitions: [
                { name: 'name', label: 'Name', type: 'string', mandatory: false, upsert: true },
                { name: 'confidence', label: 'Confidence', type: 'integer', mandatory: false, upsert: true },
              ],
            },
          }],
        },
        updateFormData,
      });

      const mappingSelect = screen.getByRole('combobox', { name: 'Map parsed values to attribute' });
      fireEvent.click(mappingSelect);
      fireEvent.click(screen.getByRole('option', { name: 'Name' }));

      expect(updateFormData).toHaveBeenCalledOnce();
      const updater = (updateFormData as ReturnType<typeof vi.fn>).mock.calls[0][0];
      const result = updater({ ...parsedFormData, mainEntityParseFieldMapping: undefined, fields: [] });
      expect(result.mainEntityParseFieldMapping).toBe('name');
    });

    it('shows the STIX-pattern and observable-creation toggles for Indicator type', () => {
      const handleFieldChange = vi.fn();
      renderSection({
        formData: { ...parsedFormData, mainEntityType: 'Indicator' },
        handleFieldChange,
      });

      fireEvent.click(screen.getByRole('checkbox', { name: 'Automatically convert to STIX patterns' }));
      expect(handleFieldChange).toHaveBeenCalledWith('mainEntityAutoConvertToStixPattern', true);

      fireEvent.click(screen.getByRole('checkbox', { name: 'Automatically create observables from indicators' }));
      expect(handleFieldChange).toHaveBeenCalledWith('autoCreateObservableFromIndicator', true);
    });

    it('shows the auto-create-indicator toggle for observable entity types', () => {
      const handleFieldChange = vi.fn();
      renderSection({
        formData: { ...parsedFormData, mainEntityType: 'File' },
        handleFieldChange,
      });

      fireEvent.click(screen.getByRole('checkbox', { name: 'Automatically create indicators from observables' }));

      expect(handleFieldChange).toHaveBeenCalledWith('autoCreateIndicatorFromObservable', true);
    });

    it('renders parsed-mode additional fields and adds a new one, excluding the mapped attribute', () => {
      const mappedField: FormFieldAttribute = {
        id: 'field-1',
        name: 'name',
        label: 'Name',
        type: 'text',
        required: false,
        attributeMapping: { entity: 'main_entity', attributeName: 'name' },
      };
      const otherField: FormFieldAttribute = {
        id: 'field-2',
        name: 'confidence',
        label: 'Confidence',
        type: 'number',
        required: false,
        attributeMapping: { entity: 'main_entity', attributeName: 'confidence' },
      };
      const renderField = vi.fn();
      const handleAddField = vi.fn();
      renderSection({
        formData: { ...parsedFormData, mainEntityParseFieldMapping: 'name' },
        fieldsByEntity: { main_entity: [mappedField, otherField] },
        renderField,
        handleAddField,
      });

      expect(renderField).toHaveBeenCalledWith(otherField, 0, 'Report', [otherField]);
      expect(renderField).not.toHaveBeenCalledWith(mappedField, expect.anything(), expect.anything(), expect.anything());

      fireEvent.click(screen.getByRole('button', { name: 'Add field' }));
      expect(handleAddField).toHaveBeenCalledWith('main_entity', 'Report');
    });
  });
});
