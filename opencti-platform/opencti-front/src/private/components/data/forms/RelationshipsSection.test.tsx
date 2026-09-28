import React from 'react';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { createTheme, ThemeProvider } from '@mui/material/styles';
import type { ThemeOptions } from '@mui/material/styles';
import { describe, expect, it, vi } from 'vitest';
import ThemeDark from '../../../../components/ThemeDark';
import type { FormBuilderData } from './Form.d';
import RelationshipsSection from './RelationshipsSection';

vi.mock('../../../../components/i18n', () => ({
  useFormatter: () => ({ t_i18n: (value: string) => value }),
}));

vi.mock('../../../../utils/hooks/useAuth', () => ({
  __esModule: true,
  default: () => ({
    schema: {
      schemaRelationsTypesMapping: new Map(),
    },
  }),
}));

vi.mock('@common/button/Button', () => ({
  __esModule: true,
  default: ({
    children,
    disabled,
    onClick,
    startIcon,
  }: {
    children: React.ReactNode;
    disabled?: boolean;
    onClick?: () => void;
    startIcon?: React.ReactNode;
  }) => (
    <button type="button" disabled={disabled} onClick={onClick}>
      {startIcon}
      {children}
    </button>
  ),
}));

const formData: FormBuilderData = {
  name: 'Relationship form',
  mainEntityType: 'Report',
  includeInContainer: false,
  isDraftByDefault: false,
  allowDraftOverride: false,
  mainEntityMultiple: false,
  additionalEntities: [
    {
      id: 'entity-1',
      entityType: 'Attack-Pattern',
      label: 'Technique',
      multiple: false,
    },
  ],
  fields: [],
  relationships: [
    {
      id: 'relationship-1',
      fromEntity: 'main_entity',
      toEntity: 'entity-1',
      relationshipType: '',
      required: false,
    },
  ],
  active: true,
};

const renderSection = (
  overrides: Partial<React.ComponentProps<typeof RelationshipsSection>> = {},
) => {
  const props: React.ComponentProps<typeof RelationshipsSection> = {
    formData,
    handleFieldChange: vi.fn(),
    updateFormData: vi.fn(),
    updateRelationshipEntity: vi.fn(),
    updateRelationshipType: vi.fn(),
    toggleRelationshipRequired: vi.fn(),
    handleRemoveRelationship: vi.fn(),
    handleAddRelationship: vi.fn(),
    ...overrides,
  };
  render(
    <ThemeProvider theme={createTheme(ThemeDark() as ThemeOptions)}>
      <RelationshipsSection {...props} />
    </ThemeProvider>,
  );
  return props;
};

describe('RelationshipsSection', () => {
  it('renders one relationship block per relationship', () => {
    renderSection({
      formData: {
        ...formData,
        relationships: [
          formData.relationships[0],
          {
            ...formData.relationships[0],
            id: 'relationship-2',
          },
        ],
      },
    });

    expect(screen.getByText('Relationship 1')).toBeInTheDocument();
    expect(screen.getByText('Relationship 2')).toBeInTheDocument();
  });

  it('calls handleAddRelationship when Add relationship is clicked', () => {
    const props = renderSection();

    fireEvent.click(screen.getByRole('button', { name: 'Add relationship' }));

    expect(props.handleAddRelationship).toHaveBeenCalledOnce();
  });

  it('calls updateRelationshipEntity with the selected source entity, letting the caller decide whether to clear the relationship type', () => {
    const props = renderSection({
      formData: {
        ...formData,
        relationships: [{
          ...formData.relationships[0],
          relationshipType: 'related-to',
        }],
      },
    });
    const sourceSelect = screen.getAllByRole('combobox')[0];

    fireEvent.click(sourceSelect);
    fireEvent.click(screen.getByRole('option', { name: 'Technique' }));

    expect(props.updateRelationshipEntity).toHaveBeenCalledWith(
      'relationship-1',
      'fromEntity',
      'entity-1',
    );
  });

  it('disables Relationship Type until both entities are selected', () => {
    renderSection({
      formData: {
        ...formData,
        relationships: [{
          ...formData.relationships[0],
          toEntity: '',
        }],
      },
    });

    expect(screen.getAllByRole('combobox')[2]).toHaveAttribute('disabled');
  });

  it('renders additional relationship fields only when a relationship type is set', () => {
    const relationshipField = {
      id: 'field-1',
      name: 'description',
      label: 'Description',
      type: 'text',
      required: false,
      attributeMapping: {
        entity: 'relationship-1',
        attributeName: 'description',
      },
    };

    renderSection();
    expect(screen.queryByText('Additional Fields')).not.toBeInTheDocument();
    cleanup();

    renderSection({
      formData: {
        ...formData,
        relationships: [{
          ...formData.relationships[0],
          relationshipType: 'related-to',
          fields: [relationshipField],
        }],
      },
    });

    expect(screen.getByText('Additional Fields')).toBeInTheDocument();
    expect(screen.getByDisplayValue('Description')).toBeInTheDocument();
  });

  it('calls updateRelationshipEntity with the selected target entity', () => {
    const props = renderSection();
    const targetSelect = screen.getAllByRole('combobox')[1];

    fireEvent.click(targetSelect);
    fireEvent.click(screen.getByRole('option', { name: 'Main Entity' }));

    expect(props.updateRelationshipEntity).toHaveBeenCalledWith(
      'relationship-1',
      'toEntity',
      'main_entity',
    );
  });

  it('selects a relationship type from the always-available related-to option', () => {
    const props = renderSection();
    const typeSelect = screen.getAllByRole('combobox')[2];

    fireEvent.click(typeSelect);
    fireEvent.click(screen.getByRole('option', { name: 'relationship_related-to' }));

    expect(props.updateRelationshipType).toHaveBeenCalledWith('relationship-1', 'related-to');
  });

  it('toggles the required switch for a relationship', () => {
    const props = renderSection();

    fireEvent.click(screen.getAllByRole('checkbox', { name: 'Required' })[0]);

    expect(props.toggleRelationshipRequired).toHaveBeenCalledWith('relationship-1', true);
  });

  it('adds a new relationship field via updateFormData', () => {
    const props = renderSection({
      formData: {
        ...formData,
        relationships: [{
          ...formData.relationships[0],
          relationshipType: 'related-to',
        }],
      },
    });

    fireEvent.click(screen.getByRole('button', { name: 'Add field' }));

    expect(props.updateFormData).toHaveBeenCalledOnce();
    const updater = (props.updateFormData as ReturnType<typeof vi.fn>).mock.calls[0][0];
    const result = updater({
      ...formData,
      relationships: [{
        ...formData.relationships[0],
        relationshipType: 'related-to',
      }],
    });
    expect(result.relationships[0].fields).toHaveLength(1);
    expect(result.relationships[0].fields[0]).toMatchObject({ label: '', type: 'text', required: false });
  });

  describe('relationship field controls', () => {
    const relationshipField = {
      id: 'field-1',
      name: 'description',
      label: 'Description',
      type: 'text',
      required: false,
      attributeMapping: {
        entity: 'relationship-1',
        attributeName: 'description',
      },
    };

    const relationshipFormData: FormBuilderData = {
      ...formData,
      relationships: [{
        ...formData.relationships[0],
        relationshipType: 'related-to',
        fields: [relationshipField],
      }],
    };

    it('updates the field label and auto-generates its name', () => {
      const props = renderSection({ formData: relationshipFormData });

      fireEvent.change(screen.getByDisplayValue('Description'), { target: { value: 'New Label!' } });

      expect(props.handleFieldChange).toHaveBeenCalledWith('relationships.0.fields.0.label', 'New Label!');
      expect(props.handleFieldChange).toHaveBeenCalledWith('relationships.0.fields.0.name', 'new_label');
    });

    it('resets the attribute mapping when the field type changes', () => {
      const props = renderSection({ formData: relationshipFormData });
      const fieldTypeSelect = screen.getAllByRole('combobox').find((select) => select.textContent === 'Text') as HTMLElement;

      fireEvent.click(fieldTypeSelect);
      fireEvent.click(screen.getByRole('option', { name: 'Number' }));

      expect(props.handleFieldChange).toHaveBeenCalledWith('relationships.0.fields.0.type', 'number');
      expect(props.handleFieldChange).toHaveBeenCalledWith('relationships.0.fields.0.attributeMapping.attributeName', '');
    });

    it('maps the field to an available attribute for its type', () => {
      const numberField = {
        ...relationshipField,
        type: 'number',
        attributeMapping: { entity: 'relationship-1', attributeName: '' },
      };
      const props = renderSection({
        formData: {
          ...formData,
          relationships: [{
            ...formData.relationships[0],
            relationshipType: 'related-to',
            fields: [numberField],
          }],
        },
      });
      const attributeSelect = screen.getAllByRole('combobox').find((select) => select.textContent === 'Select an attribute') as HTMLElement;

      fireEvent.click(attributeSelect);
      fireEvent.click(screen.getByRole('option', { name: 'Confidence' }));

      expect(props.handleFieldChange).toHaveBeenCalledWith('relationships.0.fields.0.attributeMapping.attributeName', 'confidence');
    });

    it('toggles the required switch for a relationship field', () => {
      const props = renderSection({ formData: relationshipFormData });

      fireEvent.click(screen.getAllByRole('checkbox', { name: 'Required' })[1]);

      expect(props.handleFieldChange).toHaveBeenCalledWith('relationships.0.fields.0.required', true);
    });

    it('removes a relationship field via updateFormData', () => {
      const props = renderSection({ formData: relationshipFormData });

      fireEvent.click(screen.getByRole('button', { name: 'Delete' }));

      expect(props.updateFormData).toHaveBeenCalledOnce();
      const updater = (props.updateFormData as ReturnType<typeof vi.fn>).mock.calls[0][0];
      const result = updater(relationshipFormData);
      expect(result.relationships[0].fields).toHaveLength(0);
    });
  });

  it('removes the relationship with its id', () => {
    const props = renderSection();

    fireEvent.click(screen.getByRole('button', { name: 'Remove' }));

    expect(props.handleRemoveRelationship).toHaveBeenCalledWith('relationship-1');
  });
});
