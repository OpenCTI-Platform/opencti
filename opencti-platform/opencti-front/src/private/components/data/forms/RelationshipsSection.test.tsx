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

  it('removes the relationship with its id', () => {
    const props = renderSection();

    fireEvent.click(screen.getByRole('button', { name: 'Remove' }));

    expect(props.handleRemoveRelationship).toHaveBeenCalledWith('relationship-1');
  });
});
