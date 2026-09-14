import { useCallback } from 'react';
import type { AdditionalEntity, FormBuilderData } from './Form.d';
import { generateEntityId } from './FormUtils';

export const useFormBuilderOperations = (
  updateFormData: (updater: (prev: FormBuilderData) => FormBuilderData) => void,
) => {
  const renameField = useCallback((fieldId: string, label: string) => {
    const name = label.toLowerCase().replace(/\s+/g, '_').replace(/[^a-z0-9_]/g, '');
    updateFormData((prev) => ({
      ...prev,
      fields: prev.fields.map((field) => (
        field.id === fieldId
          ? { ...field, label, name: name || field.id }
          : field
      )),
    }));
  }, [updateFormData]);

  const toggleParsedMode = useCallback((entityId: string | 'main') => {
    updateFormData((prev) => {
      if (entityId === 'main') {
        return {
          ...prev,
          mainEntityFieldMode: prev.mainEntityFieldMode === 'parsed' ? 'multiple' : 'parsed',
        };
      }

      return {
        ...prev,
        additionalEntities: prev.additionalEntities.map((entity) => (
          entity.id === entityId
            ? { ...entity, fieldMode: entity.fieldMode === 'parsed' ? 'multiple' : 'parsed' }
            : entity
        )),
      };
    });
  }, [updateFormData]);

  const addAdditionalEntity = useCallback((entityType: string) => {
    const newEntity: AdditionalEntity = {
      id: generateEntityId(),
      entityType,
      multiple: false,
      minAmount: 0,
      required: false,
      lookup: false,
      label: '',
      fieldMode: 'multiple',
      parseField: 'text',
      parseMode: 'comma',
    };

    updateFormData((prev) => ({
      ...prev,
      additionalEntities: [...prev.additionalEntities, newEntity],
    }));
  }, [updateFormData]);

  const updateRelationshipEntity = useCallback((
    relationshipId: string,
    side: 'fromEntity' | 'toEntity',
    entityId: string,
  ) => {
    updateFormData((prev) => ({
      ...prev,
      relationships: prev.relationships.map((relationship) => (
        relationship.id === relationshipId
          ? {
              ...relationship,
              [side]: entityId,
              relationshipType: relationship.relationshipType ? '' : relationship.relationshipType,
            }
          : relationship
      )),
    }));
  }, [updateFormData]);

  const updateRelationshipType = useCallback((
    relationshipId: string,
    relationshipType: string,
  ) => {
    updateFormData((prev) => ({
      ...prev,
      relationships: prev.relationships.map((relationship) => (
        relationship.id === relationshipId
          ? { ...relationship, relationshipType }
          : relationship
      )),
    }));
  }, [updateFormData]);

  const toggleRelationshipRequired = useCallback((
    relationshipId: string,
    required: boolean,
  ) => {
    updateFormData((prev) => ({
      ...prev,
      relationships: prev.relationships.map((relationship) => (
        relationship.id === relationshipId
          ? { ...relationship, required }
          : relationship
      )),
    }));
  }, [updateFormData]);

  return {
    renameField,
    toggleParsedMode,
    addAdditionalEntity,
    updateRelationshipEntity,
    updateRelationshipType,
    toggleRelationshipRequired,
  };
};
