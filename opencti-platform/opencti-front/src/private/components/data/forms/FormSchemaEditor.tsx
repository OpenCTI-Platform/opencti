import Button from '@common/button/Button';
import { Add, ArrowDownward, ArrowUpward, DeleteOutlined } from '@mui/icons-material';
// fds:keep-mui Switch/TextField predate this PR; this line only drops MUI Tab/Tabs.
import { Box, FormControlLabel, Stack, Switch, TextField, Typography } from '@mui/material';
import { IconButton, Select, SelectContent, SelectItem, SelectLabel, SelectTrigger, SelectValue, Tabs, TabsContent, TabsList, TabsTrigger } from '@filigran/design-system';
import makeStyles from '@mui/styles/makeStyles';
import { FunctionComponent, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import useAuth from '../../../../utils/hooks/useAuth';
import { getVocabularyMappingByAttribute } from '../../../../utils/vocabularyMapping';
import type { AdditionalEntity, EntityRelationship, FormBuilderData, FormFieldAttribute } from './Form.d';
import {
  buildEntityTypes,
  CONTAINER_TYPES,
  convertFormBuilderDataToSchema,
  FIELD_TYPES,
  generateEntityId,
  generateFieldId,
  generateRelationshipId,
  getAttributesForEntityType as getAttributesUtil,
  getAvailableFieldTypes,
  getInitialMandatoryFields,
} from './FormUtils';
import AdditionalEntitiesSection from './AdditionalEntitiesSection';
import MainEntitySection from './MainEntitySection';
import RelationshipsSection from './RelationshipsSection';

const useStyles = makeStyles<Theme>(() => ({
  container: {
    marginTop: 20,
  },
  tabPanel: {
    marginTop: 20,
  },
  entitySection: {
    padding: 20,
    border: '1px solid var(--border-elevation-subtle)',
    borderRadius: 4,
  },
  entityHeader: {
    display: 'flex',
    justifyContent: 'space-between',
  },
  fieldGroup: {
    padding: 15,
    borderRadius: 4,
    border: '1px solid var(--border-elevation-subtle)',
  },
  fieldHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  fieldTitle: {
    fontWeight: 600,
    fontSize: 14,
  },
  relationshipGroup: {
    padding: 15,
    borderRadius: 4,
    border: '1px solid var(--border-elevation-subtle)',
  },
  addButton: {
    marginTop: 10,
  },
  alert: {
    marginBottom: 20,
  },
}));

export interface FormSchemaEditorProps {
  initialValues?: FormBuilderData;
  entitySettings: {
    edges: ReadonlyArray<{
      node: {
        id?: string;
        target_type: string;
        mandatoryAttributes?: ReadonlyArray<string>;
        attributesDefinitions?: ReadonlyArray<{
          type: string;
          name: string;
          label?: string | null;
          mandatory: boolean;
          multiple?: boolean | null;
          upsert?: boolean;
          defaultValues?: ReadonlyArray<{ id: string; name: string }> | null;
        }>;
      };
    }>;
  };
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

  const renderField = (field: FormFieldAttribute, index: number, entityType: string, entityFields: FormFieldAttribute[]) => {
    const fieldIndex = formData.fields.findIndex((f) => f.id === field.id);
    const entityId = field.attributeMapping.entity;
    const isFirstInEntity = index === 0;
    const isLastInEntity = index === entityFields.length - 1;

    // Get all attributes for this entity type (not filtered by field type yet)
    const entity = entityTypes.find((e) => e.value === entityType);
    let allAttributes = entity?.attributes || [];

    // Add special attributes that are always available for all entity types
    const specialAttributes = [
      {
        value: 'createdBy',
        name: 'createdBy',
        label: t_i18n('Created By'),
        mandatory: false,
        type: 'ref',
      },
      {
        value: 'objectMarking',
        name: 'objectMarking',
        label: t_i18n('Marking Definitions'),
        mandatory: false,
        type: 'refs',
      },
      {
        value: 'objectLabel',
        name: 'objectLabel',
        label: t_i18n('Labels'),
        mandatory: false,
        type: 'refs',
      },
      {
        value: 'externalReferences',
        name: 'externalReferences',
        label: t_i18n('External References'),
        mandatory: false,
        type: 'refs',
      },
      {
        value: 'x_opencti_files',
        name: 'x_opencti_files',
        label: t_i18n('Files'),
        mandatory: false,
        type: 'files',
      },
      {
        value: 'x_opencti_main_observable_type',
        name: 'x_opencti_main_observable_type',
        label: t_i18n('Main observable type'),
        mandatory: false,
        type: 'types',
      },
    ];

    // Merge special attributes with entity attributes
    allAttributes = [...allAttributes, ...specialAttributes];

    // Check if we're in parsed mode
    let isInParsedMode = false;

    // Filter out parsed field mapping if in parsed mode
    if (field.attributeMapping.entity === 'main_entity' && formData.mainEntityFieldMode === 'parsed' && formData.mainEntityParseFieldMapping) {
      allAttributes = allAttributes.filter((attr) => attr.value !== formData.mainEntityParseFieldMapping);
      isInParsedMode = true;
    } else if (field.attributeMapping.entity !== 'main_entity') {
      // For additional entities, check if they're in parsed mode
      const additionalEntity = formData.additionalEntities.find((e) => e.id === field.attributeMapping.entity);
      if (additionalEntity?.fieldMode === 'parsed' && additionalEntity.parseFieldMapping) {
        allAttributes = allAttributes.filter((attr) => attr.value !== additionalEntity.parseFieldMapping);
        isInParsedMode = true;
      }
    }

    // Filter out already used attributes
    const existingFields = formData.fields
      .filter((f) => f.attributeMapping.entity === field.attributeMapping.entity && f.id !== field.id)
      .map((f) => f.attributeMapping.attributeName);
    allAttributes = allAttributes.filter((attr) => !existingFields.includes(attr.value));

    // Determine available field types based on selected attribute
    let availableFieldTypes: typeof FIELD_TYPES = [];
    if (field.attributeMapping.attributeName) {
      const selectedAttribute = allAttributes.find((attr) => attr.value === field.attributeMapping.attributeName);

      // Check if it's a special attribute first
      if (field.attributeMapping.attributeName === 'createdBy') {
        availableFieldTypes = [{ value: 'createdBy', label: 'Created By' }];
      } else if (field.attributeMapping.attributeName === 'objectMarking') {
        availableFieldTypes = [{ value: 'objectMarking', label: 'Object Marking' }];
      } else if (field.attributeMapping.attributeName === 'objectLabel') {
        availableFieldTypes = [{ value: 'objectLabel', label: 'Object Label' }];
      } else if (field.attributeMapping.attributeName === 'externalReferences') {
        availableFieldTypes = [{ value: 'externalReferences', label: 'External References' }];
      } else if (field.attributeMapping.attributeName === 'x_opencti_files') {
        availableFieldTypes = [{ value: 'files', label: 'Files' }];
      } else if (field.attributeMapping.attributeName === 'x_opencti_main_observable_type') {
        availableFieldTypes = [{ value: 'types', label: 'Types' }];
      } else {
        availableFieldTypes = getAvailableFieldTypes(entityType, entityTypes)
          .filter((fieldType) => {
            // Filter out multiselect if attribute doesn't support multiple
            if (fieldType.value === 'multiselect' && selectedAttribute && !selectedAttribute.multiple) {
              return false;
            }

            const attributesForType = getAttributesUtil(entityType, fieldType.value, entityTypes, t_i18n);
            return attributesForType.some((attr) => attr.value === field.attributeMapping.attributeName);
          });
      }
    }

    return (
      <Stack key={field.id} className={classes.fieldGroup} gap={1}>
        <div className={classes.fieldHeader}>
          <Typography className={classes.fieldTitle}>
            {field.isMandatory ? `${t_i18n('Field')} ${index + 1} (${t_i18n('Mandatory')})` : `${t_i18n('Field')} ${index + 1}`}
          </Typography>
          <div style={{ display: 'flex', alignItems: 'center' }}>
            <IconButton
              variant="default"
              priority="tertiary"
              aria-label={t_i18n('Move up')}
              size="sm"
              onClick={() => handleMoveFieldUp(entityId, field.id)}
              disabled={isFirstInEntity}
              title={t_i18n('Move up')}
              icon={<ArrowUpward fontSize="small" />}
            />
            <IconButton
              variant="default"
              priority="tertiary"
              aria-label={t_i18n('Move down')}
              size="sm"
              onClick={() => handleMoveFieldDown(entityId, field.id)}
              disabled={isLastInEntity}
              title={t_i18n('Move down')}
              icon={<ArrowDownward fontSize="small" />}
            />
            {(!field.isMandatory || isInParsedMode) && (
              <IconButton
                variant="destructive"
                priority="tertiary"
                aria-label={t_i18n('Delete')}
                size="sm"
                onClick={() => handleRemoveField(field.id)}
                icon={<DeleteOutlined fontSize="small" />}
              />
            )}
          </div>
        </div>

        <Stack gap={2}>

          <Select
            value={field.attributeMapping.attributeName}
            onValueChange={(value) => {
              const attributeName = value;
              const selectedAttribute = allAttributes.find((attr) => attr.value === attributeName);
              handleFieldChange(`fields.${fieldIndex}.attributeMapping.attributeName`, attributeName);
              // Always update label with attribute label when changing attribute
              if (selectedAttribute) {
                handleFieldChange(`fields.${fieldIndex}.label`, selectedAttribute.label || t_i18n(selectedAttribute.name));
                let name: string;
                if (['createdBy', 'objectMarking', 'objectLabel', 'externalReferences', 'x_opencti_files'].includes(attributeName)) {
                // Use the attribute name directly for special fields
                  name = attributeName === 'x_opencti_files' ? 'files' : attributeName;
                } else {
                // Auto-generate name from label for regular fields
                  name = (selectedAttribute.label || selectedAttribute.name).toLowerCase().replace(/\s+/g, '_').replace(/[^a-z0-9_]/g, '');
                }
                handleFieldChange(`fields.${fieldIndex}.name`, name || field.id);
              }
              // Check for special attributes first
              if (attributeName === 'createdBy') {
                handleFieldChange(`fields.${fieldIndex}.type`, 'createdBy');
              } else if (attributeName === 'objectMarking') {
                handleFieldChange(`fields.${fieldIndex}.type`, 'objectMarking');
              } else if (attributeName === 'objectLabel') {
                handleFieldChange(`fields.${fieldIndex}.type`, 'objectLabel');
              } else if (attributeName === 'externalReferences') {
                handleFieldChange(`fields.${fieldIndex}.type`, 'externalReferences');
              } else if (attributeName === 'x_opencti_files') {
                handleFieldChange(`fields.${fieldIndex}.type`, 'files');
              } else {
              // Determine and set an appropriate default field type for regular attributes
                const compatibleTypes = getAvailableFieldTypes(entityType, entityTypes)
                  .filter((fieldType) => {
                  // Filter out multiselect if attribute doesn't support multiple
                    if (fieldType.value === 'multiselect' && selectedAttribute && !selectedAttribute.multiple) {
                      return false;
                    }

                    const attributesForType = getAttributesUtil(entityType, fieldType.value, entityTypes, t_i18n);
                    return attributesForType.some((attr) => attr.value === attributeName);
                  });

                if (compatibleTypes.length > 0) {
                // Check if it's an OpenVocab field first - always set as default for OpenVocab attributes
                  const vocabMapping = getVocabularyMappingByAttribute(attributeName);
                  if (vocabMapping) {
                  // Always default to openvocab for OpenVocab-compatible attributes
                    handleFieldChange(`fields.${fieldIndex}.type`, 'openvocab');
                    if (vocabMapping.multiple !== undefined) {
                      handleFieldChange(`fields.${fieldIndex}.multiple`, vocabMapping.multiple);
                    }
                  } else if (!field.type || !compatibleTypes.some((t) => t.value === field.type)) {
                  // Only set a default field type if none is selected or current is incompatible
                    if (selectedAttribute?.defaultValues && selectedAttribute.defaultValues.length > 0) {
                    // If attribute has vocabulary, suggest select (not multiselect unless multiple is true)
                      const suggestedType = selectedAttribute.multiple ? 'multiselect' : 'select';
                      handleFieldChange(`fields.${fieldIndex}.type`, suggestedType);
                      if (suggestedType === 'multiselect') {
                        handleFieldChange(`fields.${fieldIndex}.multiple`, true);
                      }
                    } else {
                    // Set the first compatible type as default
                      handleFieldChange(`fields.${fieldIndex}.type`, compatibleTypes[0].value);
                    }
                  }
                }
              }
            }}
            disabled={field.isMandatory && !isInParsedMode}
          >
            <div>
              <SelectLabel>{t_i18n('Map to attribute')}</SelectLabel>
              <SelectTrigger className="w-full">
                <SelectValue placeholder={t_i18n('Select an attribute')} />
              </SelectTrigger>
              <SelectContent aria-label={t_i18n('Map to attribute')}>
                {allAttributes.map((attr) => (
                  <SelectItem key={attr.value} value={attr.value}>
                    {attr.label || t_i18n(attr.name)}
                  </SelectItem>
                ))}
              </SelectContent>
            </div>
          </Select>

          <Select
            value={field.type}
            onValueChange={(value) => {
              handleFieldChange(`fields.${fieldIndex}.type`, value);
            }}
            disabled={!field.attributeMapping.attributeName || !!getVocabularyMappingByAttribute(field.attributeMapping.attributeName)}
          >
            <div>
              <SelectLabel>{t_i18n('Field Type')}</SelectLabel>
              <SelectTrigger className="w-full">
                <SelectValue placeholder={t_i18n('Select a field type')} />
              </SelectTrigger>
              <SelectContent aria-label={t_i18n('Field Type')}>
                {availableFieldTypes.map((type) => (
                  <SelectItem key={type.value} value={type.value}>
                    {type.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </div>
          </Select>

          <TextField
            variant="outlined"
            label={t_i18n('Field Label')}
            fullWidth
            value={field.label}
            onChange={(e) => {
              const label = e.target.value;
              // Auto-generate name from label
              const name = label.toLowerCase().replace(/\s+/g, '_').replace(/[^a-z0-9_]/g, '');
              handleFieldChange(`fields.${fieldIndex}.label`, label);
              handleFieldChange(`fields.${fieldIndex}.name`, name || field.id); // Use field.id as fallback
            }}
            className="mt-2"
          />

          {(field.type === 'select' || field.type === 'multiselect') && (() => {
          // Check if the mapped attribute has vocabulary (defaultValues)
            const entityForVocab = entityTypes.find((e) => e.value === entityType);
            const attribute = entityForVocab?.attributes?.find((attr) => attr.name === field.attributeMapping.attributeName);
            const hasVocabulary = attribute?.defaultValues && attribute.defaultValues.length > 0;

            if (hasVocabulary) {
            // Use vocabulary from the attribute
              return (
                <div>
                  <Typography variant="caption">
                    {t_i18n('Options (from vocabulary)')}
                  </Typography>
                  <Typography variant="body2" color="textSecondary" style={{ marginTop: 5 }}>
                    {t_i18n('This field uses predefined vocabulary values.')}
                  </Typography>
                  <Box style={{ marginTop: 10, paddingLeft: 10 }}>
                    {attribute.defaultValues?.map((value: { id: string; name: string }) => (
                      <Typography key={value.id} variant="body2" style={{ marginTop: 5 }}>
                        • {value.name}
                      </Typography>
                    ))}
                  </Box>
                </div>
              );
            }

            // Custom options for fields without vocabulary
            return (
              <div>
                <Typography variant="caption" style={{ marginRight: 20 }}>{t_i18n('Options')}</Typography>
                {field.options?.map((option, optIndex) => (
                  <Box key={optIndex} display="flex" alignItems="center" style={{ marginTop: 10 }}>
                    <TextField
                      variant="outlined"
                      label={t_i18n('Label')}
                      value={option.label}
                      onChange={(e) => {
                        const newOptions = [...(field.options || [])];
                        newOptions[optIndex] = { ...option, label: e.target.value };
                        handleFieldChange(`fields.${fieldIndex}.options`, newOptions);
                      }}
                      style={{ flex: 1, marginRight: 10 }}
                    />
                    <TextField
                      variant="outlined"
                      label={t_i18n('Value')}
                      value={option.value}
                      onChange={(e) => {
                        const newOptions = [...(field.options || [])];
                        newOptions[optIndex] = { ...option, value: e.target.value };
                        handleFieldChange(`fields.${fieldIndex}.options`, newOptions);
                      }}
                      style={{ flex: 1, marginRight: 10 }}
                    />
                    <IconButton
                      variant="destructive"
                      priority="tertiary"
                      aria-label={t_i18n('Delete')}
                      size="sm"
                      onClick={() => {
                        const newOptions = field.options?.filter((_, i) => i !== optIndex) || [];
                        handleFieldChange(`fields.${fieldIndex}.options`, newOptions);
                      }}
                      icon={<DeleteOutlined fontSize="small" />}
                    />
                  </Box>
                ))}
                <Button
                  variant="secondary"
                  size="small"
                  startIcon={<Add fontSize="small" />}
                  onClick={() => {
                    const newOptions = [...(field.options || []), { label: '', value: '' }];
                    handleFieldChange(`fields.${fieldIndex}.options`, newOptions);
                  }}
                  style={{ marginTop: 10 }}
                >
                  {t_i18n('Add option')}
                </Button>
              </div>
            );
          })()}

          {/* Default value field for text, number, textarea, select, and date fields */}
          {(field.type === 'text' || field.type === 'textarea' || field.type === 'number' || field.type === 'date' || field.type === 'datetime' || field.type === 'select') && (
            <TextField
              variant="outlined"
              label={t_i18n('Default value')}
              fullWidth
              value={field.defaultValue || ''}
              onChange={(e) => {
                const { value: targetValue } = e.target;
                let value: string | number | null = targetValue;
                if (field.type === 'number') {
                  value = targetValue === '' ? null : Number(targetValue);
                }
                handleFieldChange(`fields.${fieldIndex}.defaultValue`, value);
              }}
              type={field.type === 'number' ? 'number' : 'text'}
              helperText={(() => {
                if (field.type === 'datetime' || field.type === 'date') {
                  return t_i18n('Enter date in ISO format (e.g., 2024-01-01 or 2024-01-01T10:00:00.000Z)');
                }
                if (field.type === 'select' && field.options) {
                  return t_i18n('Enter a value from the options');
                }
                return '';
              })()}
            />
          )}

          {/* Default value for checkbox/toggle */}
          {(field.type === 'checkbox' || field.type === 'toggle') && (
            <Select
              value={(() => {
                if (field.defaultValue === true) return 'true';
                if (field.defaultValue === false) return 'false';
                return 'none';
              })()}
              onValueChange={(value) => {
                const val = value;
                if (val === 'true') {
                  handleFieldChange(`fields.${fieldIndex}.defaultValue`, true);
                } else if (val === 'false') {
                  handleFieldChange(`fields.${fieldIndex}.defaultValue`, false);
                } else {
                  handleFieldChange(`fields.${fieldIndex}.defaultValue`, null);
                }
              }}
            >
              <SelectLabel>{t_i18n('Default value')}</SelectLabel>
              <SelectTrigger className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent aria-label={t_i18n('Default value')}>
                <SelectItem value="none">{t_i18n('No default')}</SelectItem>
                <SelectItem value="true">{t_i18n('Default checked (true)')}</SelectItem>
                <SelectItem value="false">{t_i18n('Default unchecked (false)')}</SelectItem>
              </SelectContent>
            </Select>
          )}

          <Select
            value={field.width || 'full'}
            onValueChange={(value) => handleFieldChange(`fields.${fieldIndex}.width`, value)}
          >
            <div>
              <SelectLabel>{t_i18n('Field Width')}</SelectLabel>
              <SelectTrigger className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent aria-label={t_i18n('Field Width')}>
                <SelectItem value="full">{t_i18n('Full width')}</SelectItem>
                <SelectItem value="half">{t_i18n('Half width')}</SelectItem>
                <SelectItem value="third">{t_i18n('Third width')}</SelectItem>
              </SelectContent>
            </div>
          </Select>

          {/* Multiple files option for files type */}
          {field.type === 'files' && (
            <FormControlLabel
              control={(
                <Switch
                  checked={field.multiple === true}
                  onChange={(e) => handleFieldChange(`fields.${fieldIndex}.multiple`, e.target.checked)}
                />
              )}
              label={t_i18n('Allow multiple files')}
            />
          )}

          <FormControlLabel
            control={(
              <Switch
                checked={field.isReadOnly || false}
                onChange={(e) => handleFieldChange(`fields.${fieldIndex}.isReadOnly`, e.target.checked)}
              />
            )}
            label={t_i18n('Not editable by user')}
          />

          <FormControlLabel
            control={(
              <Switch
                checked={field.required}
                onChange={(e) => handleFieldChange(`fields.${fieldIndex}.required`, e.target.checked)}
                disabled={field.isMandatory && !isInParsedMode}
              />
            )}
            label={t_i18n('Required')}
          />
        </Stack>
      </Stack>
    );
  };

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
            tabPanelClassName={classes.tabPanel}
            alertClassName={classes.alert}
            addButtonClassName={classes.addButton}
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
            tabPanelClassName={classes.tabPanel}
            entitySectionClassName={classes.entitySection}
            entityHeaderClassName={classes.entityHeader}
            addButtonClassName={classes.addButton}
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
              tabPanelClassName={classes.tabPanel}
              relationshipGroupClassName={classes.relationshipGroup}
              fieldGroupClassName={classes.fieldGroup}
              fieldHeaderClassName={classes.fieldHeader}
              fieldTitleClassName={classes.fieldTitle}
              addButtonClassName={classes.addButton}
            />
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default FormSchemaEditor;
