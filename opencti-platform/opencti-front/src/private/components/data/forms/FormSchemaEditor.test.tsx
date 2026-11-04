import React from 'react';
import { fireEvent, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import testRender from '../../../../utils/tests/test-render';
import FormSchemaEditor, { type FormSchemaEditorProps } from './FormSchemaEditor';
import type { EntitySettings, FormBuilderData } from './Form.d';

vi.mock('../../../../utils/hooks/useAuth', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../../utils/hooks/useAuth')>();
  return {
    ...actual,
    __esModule: true,
    default: () => ({
      schema: {
        sdos: [{ id: 'Report', label: 'Report' }, { id: 'Indicator', label: 'Indicator' }],
        scos: [],
        smos: [],
        schemaRelationsTypesMapping: new Map(),
      },
    }),
  };
});

let lastMainEntityProps: Record<string, unknown> | undefined;
let lastAdditionalEntitiesProps: Record<string, unknown> | undefined;
let lastRelationshipsProps: Record<string, unknown> | undefined;

vi.mock('./MainEntitySection', () => ({
  __esModule: true,
  default: (props: Record<string, unknown>) => {
    lastMainEntityProps = props;
    return (
      <div>
        <button
          type="button"
          onClick={() => (props.handleMainEntityTypeChange as (v: string) => void)('Indicator')}
        >
          change-main-entity-type
        </button>
        <button
          type="button"
          onClick={() => (props.handleAddField as (e: string, t: string) => void)('main_entity', 'Report')}
        >
          add-main-field
        </button>
        <span>isContainer:{String(props.isContainer)}</span>
      </div>
    );
  },
}));

vi.mock('./AdditionalEntitiesSection', () => ({
  __esModule: true,
  default: (props: Record<string, unknown>) => {
    lastAdditionalEntitiesProps = props;
    return (
      <button type="button" onClick={props.handleAddAdditionalEntity as () => void}>
        add-additional-entity
      </button>
    );
  },
}));

vi.mock('./RelationshipsSection', () => ({
  __esModule: true,
  default: (props: Record<string, unknown>) => {
    lastRelationshipsProps = props;
    return (
      <button
        type="button"
        onClick={() => (props.handleRemoveRelationship as (id: string) => void)('rel-1')}
      >
        remove-relationship
      </button>
    );
  },
}));

const entitySettings: EntitySettings = {
  edges: [
    {
      node: {
        target_type: 'Report',
        attributesDefinitions: [
          { name: 'name', label: 'Name', type: 'string', mandatory: true },
        ],
      },
    },
    {
      node: {
        target_type: 'Indicator',
        attributesDefinitions: [
          { name: 'pattern', label: 'Pattern', type: 'string', mandatory: true },
        ],
      },
    },
  ],
};

const renderEditor = (overrides: Partial<FormSchemaEditorProps> = {}) => {
  const onChange = vi.fn();
  const onSchemaChange = vi.fn();
  const result = testRender(
    <FormSchemaEditor
      entitySettings={entitySettings}
      onChange={onChange}
      onSchemaChange={onSchemaChange}
      {...overrides}
    />,
  );
  return { ...result, onChange, onSchemaChange };
};

describe('FormSchemaEditor', () => {
  it('renders the Main Entity tab by default with mandatory fields pre-populated', () => {
    const { onChange } = renderEditor();

    expect(screen.getByRole('tab', { name: 'Main Entity' })).toHaveAttribute('data-state', 'active');
    expect(onChange).toHaveBeenCalled();
    const initialData = onChange.mock.calls[0][0] as FormBuilderData;
    expect(initialData.fields).toHaveLength(1);
    expect(initialData.fields[0]).toMatchObject({ name: 'name', isMandatory: true });
    expect(lastMainEntityProps?.isContainer).toBe(true);
  });

  it('does not show the Relationships tab without additional entities', () => {
    renderEditor();

    expect(screen.queryByRole('tab', { name: 'Relationships' })).not.toBeInTheDocument();
  });

  it('shows the Relationships tab once additional entities exist', () => {
    renderEditor({
      initialValues: {
        name: 'Test',
        mainEntityType: 'Report',
        includeInContainer: true,
        isDraftByDefault: false,
        allowDraftOverride: false,
        mainEntityMultiple: false,
        additionalEntities: [{ id: 'entity-1', entityType: 'Indicator', label: 'Related Indicator', multiple: false }],
        fields: [],
        relationships: [],
        active: true,
      },
    });

    expect(screen.getByRole('tab', { name: 'Relationships' })).toBeInTheDocument();
  });

  it('switches tabs and recomputes fields when the main entity type changes', () => {
    renderEditor();

    fireEvent.click(screen.getByRole('button', { name: 'change-main-entity-type' }));

    expect(lastMainEntityProps?.formData).toMatchObject({ mainEntityType: 'Indicator' });
    const fields = (lastMainEntityProps?.formData as FormBuilderData).fields;
    expect(fields.some((f) => f.name === 'pattern')).toBe(true);
    expect(fields.some((f) => f.name === 'name')).toBe(false);
  });

  it('adds a new field via handleAddField', () => {
    renderEditor();
    const initialFieldCount = (lastMainEntityProps?.fieldsByEntity as Record<string, unknown[]>).main_entity?.length ?? 0;

    fireEvent.click(screen.getByRole('button', { name: 'add-main-field' }));

    const updatedFieldCount = (lastMainEntityProps?.fieldsByEntity as Record<string, unknown[]>).main_entity?.length ?? 0;
    expect(updatedFieldCount).toBe(initialFieldCount + 1);
  });

  it('adds an additional entity via the Additional Entities tab callback', async () => {
    const { user } = renderEditor();

    await user.click(screen.getByRole('tab', { name: 'Additional Entities' }));
    await user.click(screen.getByRole('button', { name: 'add-additional-entity' }));

    expect((lastAdditionalEntitiesProps?.formData as FormBuilderData).additionalEntities).toHaveLength(1);
  });

  it('removes a relationship through the Relationships tab callback', async () => {
    const { user } = renderEditor({
      initialValues: {
        name: 'Test',
        mainEntityType: 'Report',
        includeInContainer: true,
        isDraftByDefault: false,
        allowDraftOverride: false,
        mainEntityMultiple: false,
        additionalEntities: [{ id: 'entity-1', entityType: 'Indicator', label: 'Related Indicator', multiple: false }],
        fields: [],
        relationships: [{ id: 'rel-1', fromEntity: 'main_entity', toEntity: 'entity-1', relationshipType: 'related-to', required: false }],
        active: true,
      },
    });

    await user.click(screen.getByRole('tab', { name: 'Relationships' }));
    await user.click(screen.getByRole('button', { name: 'remove-relationship' }));

    expect((lastRelationshipsProps?.formData as FormBuilderData).relationships).toHaveLength(0);
  });
});
