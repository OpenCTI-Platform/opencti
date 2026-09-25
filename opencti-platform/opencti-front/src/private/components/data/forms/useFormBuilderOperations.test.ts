import { act, renderHook } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import type { FormBuilderData } from './Form.d';
import { useFormBuilderOperations } from './useFormBuilderOperations';

const createBaseData = (): FormBuilderData => ({
  name: 'Test form',
  description: '',
  mainEntityType: 'Report',
  includeInContainer: false,
  isDraftByDefault: false,
  allowDraftOverride: false,
  mainEntityMultiple: true,
  mainEntityLookup: false,
  mainEntityFieldMode: 'multiple',
  mainEntityParseField: 'text',
  mainEntityParseMode: 'comma',
  autoCreateIndicatorFromObservable: false,
  autoCreateObservableFromIndicator: false,
  additionalEntities: [{
    id: 'entity-1',
    entityType: 'Indicator',
    label: 'Indicators',
    multiple: true,
    fieldMode: 'multiple',
  }],
  fields: [
    {
      id: 'field-1',
      name: 'old_label',
      label: 'Old Label',
      type: 'text',
      required: false,
      attributeMapping: {
        entity: 'main_entity',
        attributeName: 'name',
      },
    },
    {
      id: 'field-2',
      name: 'other_field',
      label: 'Other Field',
      type: 'text',
      required: false,
      attributeMapping: {
        entity: 'main_entity',
        attributeName: 'description',
      },
    },
  ],
  relationships: [],
  active: true,
});

const renderOperations = () => {
  let current = createBaseData();
  const updateFormData = (updater: (prev: FormBuilderData) => FormBuilderData) => {
    current = updater(current);
  };
  const hook = renderHook(() => useFormBuilderOperations(updateFormData));
  return { ...hook, getCurrent: () => current };
};

describe('useFormBuilderOperations', () => {
  it('renames only the target field and preserves the current label-to-name normalization', () => {
    const { result, getCurrent } = renderOperations();

    act(() => result.current.renameField('field-1', 'New Label'));

    expect(getCurrent().fields).toEqual([
      expect.objectContaining({ id: 'field-1', label: 'New Label', name: 'new_label' }),
      expect.objectContaining({ id: 'field-2', label: 'Other Field', name: 'other_field' }),
    ]);
  });

  it('sets the main entity to the explicitly selected mode', () => {
    const { result, getCurrent } = renderOperations();

    act(() => result.current.toggleParsedMode('main', 'parsed'));
    expect(getCurrent().mainEntityFieldMode).toBe('parsed');

    act(() => result.current.toggleParsedMode('main', 'multiple'));
    expect(getCurrent().mainEntityFieldMode).toBe('multiple');
  });

  it('sets an additional entity to the explicitly selected mode', () => {
    const { result, getCurrent } = renderOperations();

    act(() => result.current.toggleParsedMode('entity-1', 'parsed'));
    expect(getCurrent().additionalEntities[0].fieldMode).toBe('parsed');

    act(() => result.current.toggleParsedMode('entity-1', 'multiple'));
    expect(getCurrent().additionalEntities[0].fieldMode).toBe('multiple');
  });

  it('sets an additional entity with an omitted (legacy/imported) fieldMode to the explicitly selected mode, not a same-value flip', () => {
    const { result, getCurrent } = renderOperations();
    getCurrent().additionalEntities[0].fieldMode = undefined;

    act(() => result.current.toggleParsedMode('entity-1', 'multiple'));

    // Selecting "Multiple fields" on an entity with no prior mode must land on 'multiple',
    // not silently flip an undefined value to 'parsed'.
    expect(getCurrent().additionalEntities[0].fieldMode).toBe('multiple');
  });

  it('adds an additional entity with the existing default shape', () => {
    const { result, getCurrent } = renderOperations();

    act(() => result.current.addAdditionalEntity('Attack-Pattern'));

    expect(getCurrent().additionalEntities).toHaveLength(2);
    expect(getCurrent().additionalEntities[1]).toEqual(expect.objectContaining({
      entityType: 'Attack-Pattern',
      label: '',
      multiple: false,
      minAmount: 0,
      required: false,
      lookup: false,
      fieldMode: 'multiple',
      parseField: 'text',
      parseMode: 'comma',
    }));
    expect(getCurrent().additionalEntities[1].id).toMatch(/^entity-/);
  });

  it('updates a relationship entity and clears an existing relationship type', () => {
    const { result, getCurrent } = renderOperations();
    const relationship = {
      id: 'relationship-1',
      fromEntity: 'main_entity',
      toEntity: 'entity-1',
      relationshipType: 'related-to',
      required: false,
    };
    getCurrent().relationships.push(relationship);

    act(() => result.current.updateRelationshipEntity('relationship-1', 'fromEntity', 'entity-2'));

    expect(getCurrent().relationships).toContainEqual({
      ...relationship,
      fromEntity: 'entity-2',
      relationshipType: '',
    });
  });

  it('updates a relationship type', () => {
    const { result, getCurrent } = renderOperations();
    getCurrent().relationships.push({
      id: 'relationship-1',
      fromEntity: 'main_entity',
      toEntity: 'entity-1',
      relationshipType: '',
      required: false,
    });

    act(() => result.current.updateRelationshipType('relationship-1', 'related-to'));

    expect(getCurrent().relationships[0].relationshipType).toBe('related-to');
  });

  it('toggles relationship required state', () => {
    const { result, getCurrent } = renderOperations();
    getCurrent().relationships.push({
      id: 'relationship-1',
      fromEntity: 'main_entity',
      toEntity: 'entity-1',
      relationshipType: '',
      required: false,
    });

    act(() => result.current.toggleRelationshipRequired('relationship-1', true));

    expect(getCurrent().relationships[0].required).toBe(true);
  });
});
