import { Tabs, TabsContent, TabsList, TabsTrigger } from '@filigran/design-system';
import { FunctionComponent, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useFormatter } from '../../../../components/i18n';
import useAuth from '../../../../utils/hooks/useAuth';
import type { AdditionalEntity, EntityRelationship, EntitySettings, FormBuilderData, FormFieldAttribute } from './Form.d';
import {
  buildEntityTypes,
  CONTAINER_TYPES,
  convertFormBuilderDataToSchema,
  generateEntityId,
  generateFieldId,
  generateRelationshipId,
  getInitialMandatoryFields,
} from './FormUtils';
import AdditionalEntitiesSection from './AdditionalEntitiesSection';
import MainEntitySection from './MainEntitySection';
import RelationshipsSection from './RelationshipsSection';
import useFieldRenderer from './useFieldRenderer';
import useStyles from './useFormSchemaEditorStyles';

export interface FormSchemaEditorProps {
  initialValues?: FormBuilderData;
  entitySettings: EntitySettings;
  onChange?: (values: FormBuilderData) => void;
  onSchemaChange?: (schema: string) => void;
}

const FormSchemaEditor: FunctionComponent<FormSchemaEditorProps> = ({
  initialValues,
  entitySettings,
  onChange,
  onSchemaChange,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const { schema } = useAuth();
  const [currentTab, setCurrentTab] = useState('main');

  const entityTypes = useMemo(() => {
    if (!schema || !entitySettings) {
      return [];
    }
    return buildEntityTypes(schema, entitySettings, t_i18n);
  }, [schema, entitySettings, t_i18n]);

  const [formData, setFormData] = useState<FormBuilderData>(() => {
    if (initialValues) {
      return initialValues;
    }

    const defaultEntityType = 'Report';
    const defaultMandatoryFields = entityTypes.length > 0
      ? getInitialMandatoryFields(defaultEntityType, entityTypes, t_i18n)
      : [];

    const isDefaultContainer = CONTAINER_TYPES.includes(defaultEntityType);
    return {
      name: '',
      description: '',
      mainEntityType: defaultEntityType,
      includeInContainer: isDefaultContainer, // Default to true for containers
      isDraftByDefault: false, // Default to false
      allowDraftOverride: false, // Default to false (checkbox disabled by default)
      mainEntityMultiple: false,
      mainEntityLookup: false,
      mainEntityFieldMode: 'multiple',
      mainEntityParseField: 'text',
      mainEntityParseMode: 'comma',
      autoCreateIndicatorFromObservable: false,
      autoCreateObservableFromIndicator: false,
      additionalEntities: [],
      fields: defaultMandatoryFields,
      relationships: [],
      active: true,
    };
  });

  useEffect(() => {
    if (entityTypes.length > 0 && formData.fields.length === 0 && !initialValues) {
      const defaultMandatoryFields = getInitialMandatoryFields(formData.mainEntityType, entityTypes, t_i18n);
      setFormData((prev) => ({
        ...prev,
        fields: defaultMandatoryFields,
      }));
    }
  }, [entityTypes, formData.mainEntityType, formData.fields.length, t_i18n, initialValues]);

  // Notify parent after formData changes (never call parent setState inside a state updater)
  const isFirstRender = useRef(true);
  useEffect(() => {
    if (isFirstRender.current) {
      isFirstRender.current = false;
      if (!initialValues && onChange) {
        onChange(formData);
      }
      return;
    }
    if (onChange) {
      onChange(formData);
    }
    if (onSchemaChange) {
      const formSchema = convertFormBuilderDataToSchema(formData);
      onSchemaChange(JSON.stringify(formSchema, null, 2));
    }
  }, [formData]);

  const updateFormData = useCallback((updater: (prev: FormBuilderData) => FormBuilderData) => {
    setFormData((prev) => updater(prev));
  }, []);

  const mainEntityInfo = entityTypes.find((e) => e.value === formData.mainEntityType);
  const isContainer = mainEntityInfo?.isContainer || false;
  const hasAdditionalEntities = formData.additionalEntities.length > 0;

  const fieldsByEntity = formData.fields.reduce((acc, field) => {
    const entityId = field.attributeMapping.entity;
    if (!acc[entityId]) {
      acc[entityId] = [];
    }
    acc[entityId].push(field);
    return acc;
  }, {} as Record<string, FormFieldAttribute[]>);

  const handleMainEntityTypeChange = (value: string) => {
    updateFormData((prev) => {
      // Don't add mandatory fields if we're in parsed mode
      const shouldAddMandatoryFields = prev.mainEntityFieldMode !== 'parsed';
      const newMandatoryFields = shouldAddMandatoryFields ? getInitialMandatoryFields(value, entityTypes, t_i18n) : [];
      const nonMandatoryFields = prev.fields.filter(
        (f) => !f.isMandatory || f.attributeMapping.entity !== 'main_entity',
      );

      // Check if new type is a container and update includeInContainer
      const isNewContainer = CONTAINER_TYPES.includes(value);

      return {
        ...prev,
        mainEntityType: value,
        includeInContainer: isNewContainer, // Update includeInContainer based on new type
        fields: [...nonMandatoryFields, ...newMandatoryFields],
      };
    });
  };

  const handleFieldChange = (path: string, value: unknown) => {
    updateFormData((prev) => {
      const keys = path.split('.');
      // Prevent prototype pollution by blocking dangerous property names
      const forbiddenProps = ['__proto__', 'constructor', 'prototype'];
      // Defensive: check each key in the path at moment of access, not just at start
      const newData = { ...prev };
      let current: Record<string, unknown> = newData as Record<string, unknown>;

      for (let i = 0; i < keys.length - 1; i += 1) {
        const key = keys[i];
        if (forbiddenProps.includes(key)) {
          // Blocked prototype-polluting key in handleFieldChange (at traversal)
          return prev;
        }
        if (Array.isArray(current[key])) {
          current[key] = [...current[key]];
        } else if (typeof current[key] === 'object' && current[key] !== null) {
          current[key] = { ...current[key] };
        } else if (current[key] === undefined) {
          current[key] = {};
        }
        current = current[key] as Record<string, unknown>;
      }
      const lastKey = keys[keys.length - 1];
      if (forbiddenProps.includes(lastKey)) {
        // Blocked prototype-polluting key in handleFieldChange (at leaf)
        return prev;
      }
      current[lastKey] = value;

      // Auto-set required flag for single additional entities with default values
      // Check if we're setting a default value for a field in an additional entity
      if (path.includes('fields.') && path.endsWith('.defaultValue')) {
        const fieldMatch = path.match(/fields\.(\d+)\.defaultValue/);
        if (fieldMatch) {
          const fieldIndex = parseInt(fieldMatch[1], 10);
          const field = (newData as FormBuilderData).fields[fieldIndex];

          if (field && field.attributeMapping.entity !== 'main_entity') {
            // This field belongs to an additional entity
            const entityId = field.attributeMapping.entity;
            const additionalEntity = (newData as FormBuilderData).additionalEntities.find((e) => e.id === entityId);

            // Only apply auto-require logic for single (not multiple) additional entities
            if (additionalEntity && !additionalEntity.multiple) {
              // Check if any field in this entity has a non-empty default value
              const entityHasDefaultValues = (newData as FormBuilderData).fields.some((f) => {
                if (f.attributeMapping.entity !== entityId) return false;

                // If this is the field being updated, use the new value
                if (f.id === field.id) {
                  return value !== null && value !== undefined && value !== '';
                }

                // Check existing default values
                return f.defaultValue !== null && f.defaultValue !== undefined && f.defaultValue !== '';
              });

              // Update the entity's required flag
              const entityIndex = (newData as FormBuilderData).additionalEntities.findIndex((e) => e.id === entityId);
              if (entityIndex >= 0) {
                ((newData as FormBuilderData).additionalEntities[entityIndex] as AdditionalEntity).required = entityHasDefaultValues;
              }
            }
          }
        }
      }

      return newData;
    });
  };

  const handleAddField = (entityId: string, entityType: string) => {
    const fieldId = generateFieldId();
    const newField: FormFieldAttribute = {
      id: fieldId,
      name: fieldId,
      label: '',
      type: 'text', // Default type
      required: false,
      defaultValue: null,
      attributeMapping: {
        entity: entityId,
        attributeName: '',
        mappingType: entityId === 'main_entity' ? 'direct' : 'nested',
      },
      entityType,
      isMandatory: false,
    };

    updateFormData((prev) => ({
      ...prev,
      fields: [...prev.fields, newField],
    }));
  };

  const handleAddAdditionalEntity = () => {
    const newEntity: AdditionalEntity = {
      id: generateEntityId(),
      entityType: 'Attack-Pattern',
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
  };

  const handleAddRelationship = () => {
    const newRelationship: EntityRelationship = {
      id: generateRelationshipId(),
      fromEntity: 'main_entity',
      toEntity: '',
      relationshipType: '',
      required: false,
    };

    updateFormData((prev) => ({
      ...prev,
      relationships: [...prev.relationships, newRelationship],
    }));
  };

  const handleRemoveField = (fieldId: string) => {
    updateFormData((prev) => ({
      ...prev,
      fields: prev.fields.filter((f) => f.id !== fieldId),
    }));
  };

  const handleRemoveAdditionalEntity = (entityId: string) => {
    updateFormData((prev) => ({
      ...prev,
      additionalEntities: prev.additionalEntities.filter((e) => e.id !== entityId),
      fields: prev.fields.filter((f) => f.attributeMapping.entity !== entityId),
      relationships: prev.relationships.filter((r) => r.fromEntity !== entityId && r.toEntity !== entityId),
    }));
  };

  const handleRemoveRelationship = (relationshipId: string) => {
    updateFormData((prev) => ({
      ...prev,
      relationships: prev.relationships.filter((r) => r.id !== relationshipId),
    }));
  };

  const handleMoveFieldUp = (entityId: string, fieldId: string) => {
    updateFormData((prev) => {
      // Get fields for this entity in their current order
      const entityFields = prev.fields.filter((f) => f.attributeMapping.entity === entityId);
      const otherFields = prev.fields.filter((f) => f.attributeMapping.entity !== entityId);

      // Find the index of the field within entity fields
      const fieldIndex = entityFields.findIndex((f) => f.id === fieldId);
      if (fieldIndex <= 0) return prev; // Can't move up if already at top

      // Swap with the previous field
      const newEntityFields = [...entityFields];
      [newEntityFields[fieldIndex - 1], newEntityFields[fieldIndex]] = [newEntityFields[fieldIndex], newEntityFields[fieldIndex - 1]];

      // Reconstruct fields array maintaining entity grouping
      return {
        ...prev,
        fields: [...otherFields, ...newEntityFields].sort((a, b) => {
          // Keep entity groups together, but use new order within each group
          if (a.attributeMapping.entity === b.attributeMapping.entity) {
            const aIdx = newEntityFields.findIndex((f) => f.id === a.id);
            const bIdx = newEntityFields.findIndex((f) => f.id === b.id);
            if (aIdx !== -1 && bIdx !== -1) return aIdx - bIdx;
          }
          return 0;
        }),
      };
    });
  };

  const handleMoveFieldDown = (entityId: string, fieldId: string) => {
    updateFormData((prev) => {
      // Get fields for this entity in their current order
      const entityFields = prev.fields.filter((f) => f.attributeMapping.entity === entityId);
      const otherFields = prev.fields.filter((f) => f.attributeMapping.entity !== entityId);

      // Find the index of the field within entity fields
      const fieldIndex = entityFields.findIndex((f) => f.id === fieldId);
      if (fieldIndex < 0 || fieldIndex >= entityFields.length - 1) return prev; // Can't move down if already at bottom

      // Swap with the next field
      const newEntityFields = [...entityFields];
      [newEntityFields[fieldIndex], newEntityFields[fieldIndex + 1]] = [newEntityFields[fieldIndex + 1], newEntityFields[fieldIndex]];

      // Reconstruct fields array maintaining entity grouping
      return {
        ...prev,
        fields: [...otherFields, ...newEntityFields].sort((a, b) => {
          // Keep entity groups together, but use new order within each group
          if (a.attributeMapping.entity === b.attributeMapping.entity) {
            const aIdx = newEntityFields.findIndex((f) => f.id === a.id);
            const bIdx = newEntityFields.findIndex((f) => f.id === b.id);
            if (aIdx !== -1 && bIdx !== -1) return aIdx - bIdx;
          }
          return 0;
        }),
      };
    });
  };

  const renderField = useFieldRenderer({
    formData,
    entityTypes,
    handleFieldChange,
    handleMoveFieldUp,
    handleMoveFieldDown,
    handleRemoveField,
  });

  return (
    <div className={classes.container}>
      <Tabs value={currentTab} onValueChange={setCurrentTab}>
        <TabsList className="mb-6">
          <TabsTrigger value="main">{t_i18n('Main Entity')}</TabsTrigger>
          <TabsTrigger value="additional">{t_i18n('Additional Entities')}</TabsTrigger>
          {hasAdditionalEntities && <TabsTrigger value="relationships">{t_i18n('Relationships')}</TabsTrigger>}
        </TabsList>

        <TabsContent value="main">
          <MainEntitySection
            formData={formData}
            handleFieldChange={handleFieldChange}
            updateFormData={updateFormData}
            entityTypes={entityTypes}
            handleMainEntityTypeChange={handleMainEntityTypeChange}
            isContainer={isContainer}
            entitySettings={entitySettings}
            fieldsByEntity={fieldsByEntity}
            renderField={renderField}
            handleAddField={handleAddField}
          />
        </TabsContent>

        <TabsContent value="additional">
          <AdditionalEntitiesSection
            formData={formData}
            handleFieldChange={handleFieldChange}
            updateFormData={updateFormData}
            entityTypes={entityTypes}
            fieldsByEntity={fieldsByEntity}
            handleRemoveAdditionalEntity={handleRemoveAdditionalEntity}
            entitySettings={entitySettings}
            renderField={renderField}
            handleAddField={handleAddField}
            handleAddAdditionalEntity={handleAddAdditionalEntity}
          />
        </TabsContent>

        <TabsContent value="relationships">
          {hasAdditionalEntities && (
            <RelationshipsSection
              formData={formData}
              handleFieldChange={handleFieldChange}
              updateFormData={updateFormData}
              handleRemoveRelationship={handleRemoveRelationship}
              handleAddRelationship={handleAddRelationship}
            />
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default FormSchemaEditor;
