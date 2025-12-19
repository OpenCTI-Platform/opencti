import React, { FunctionComponent, useState, useMemo, useCallback, useEffect } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { Add, DeleteOutlined, AddCircleOutlined } from '@mui/icons-material';
import { Box, IconButton, MenuItem, Tab, Tabs, Typography, TextField, Alert, Select, FormControl, InputLabel, Switch, FormControlLabel } from '@mui/material';
import Button from '@common/button/Button';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import {
  buildEntityTypes,
  convertFormBuilderDataToSchema,
  generateEntityId,
  generateFieldId,
  generateRelationshipId,
  getAttributesForEntityType as getAttributesUtil,
  getAvailableFieldTypes,
  getInitialMandatoryFields,
  CONTAINER_TYPES,
  FIELD_TYPES,
} from './FormUtils';
import { resolveRelationsTypes } from '../../../../utils/Relation';
import { getVocabularyMappingByAttribute } from '../../../../utils/vocabularyMapping';
import type { FormFieldAttribute, AdditionalEntity, EntityRelationship, FormBuilderData, RelationshipTypeOption } from './Form.d';
import useAuth from '../../../../utils/hooks/useAuth';

const useStyles = makeStyles<Theme>((theme) => ({
  container: {
    marginTop: 20,
  },
  tabPanel: {
    marginTop: 20,
  },
  entitySection: {
    marginBottom: 30,
    padding: 20,
    border: `1px solid ${theme.palette.divider}`,
    borderRadius: 4,
  },
  entityHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    marginBottom: 20,
  },
  fieldGroup: {
    marginBottom: 20,
    padding: 15,
    backgroundColor: theme.palette.background.paper,
    borderRadius: 4,
    border: `1px solid ${theme.palette.divider}`,
  },
  fieldHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 10,
  },
  fieldTitle: {
    fontWeight: 600,
    fontSize: 14,
  },
  relationshipGroup: {
    marginBottom: 20,
    padding: 15,
    backgroundColor: theme.palette.background.paper,
    borderRadius: 4,
  },
  addButton: {
    marginTop: 10,
  },
  alert: {
    marginBottom: 20,
  },
}));

interface FormSchemaEditorProps {
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
  const [currentTab, setCurrentTab] = useState(0);

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

  // Call onChange only when component mounts to ensure parent has the initial data
  useEffect(() => {
    if (onChange && !initialValues) {
      onChange(formData);
    }
  }, []);

  const updateFormData = useCallback((updater: (prev: FormBuilderData) => FormBuilderData) => {
    setFormData((prev) => {
      const newData = updater(prev);
      if (onChange) {
        onChange(newData);
      }
      if (onSchemaChange) {
        const formSchema = convertFormBuilderDataToSchema(newData);
        onSchemaChange(JSON.stringify(formSchema, null, 2));
      }
      return newData;
    });
  }, [onChange, onSchemaChange]);

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

  const handleFieldChange = (path: string, value: string | number | boolean | string[] | Date | null | Array<{ label: string; value: string }>) => {
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

  const renderRelationshipField = (field: FormFieldAttribute, index: number, relationshipIndex: number) => {
    const fieldPath = `relationships.${relationshipIndex}.fields.${index}`;
    // Available field types for relationships - exclude checkbox, select, multiselect
    const availableFieldTypes = [
      { value: 'text', label: t_i18n('Text') },
      { value: 'textarea', label: t_i18n('Textarea') },
      { value: 'number', label: t_i18n('Number') },
      { value: 'datetime', label: t_i18n('Date/Time') },
      { value: 'date', label: t_i18n('Date') },
      { value: 'createdBy', label: t_i18n('Created By') },
      { value: 'objectMarking', label: t_i18n('Object Marking') },
      { value: 'objectLabel', label: t_i18n('Object Label') },
    ];

    // Available attributes for relationships based on field type
    const getAvailableAttributesForType = (fieldType: string) => {
      switch (fieldType) {
        case 'text':
        case 'textarea':
          return [
            { value: 'description', label: t_i18n('Description') },
          ];
        case 'number':
          return [
            { value: 'confidence', label: t_i18n('Confidence') },
            { value: 'x_opencti_workflow_id', label: t_i18n('Status') },
          ];
        case 'datetime':
        case 'date':
          return [
            { value: 'start_time', label: t_i18n('Start time') },
            { value: 'stop_time', label: t_i18n('Stop time') },
          ];
        case 'createdBy':
          return [
            { value: 'createdBy', label: t_i18n('Created By') },
          ];
        case 'objectMarking':
          return [
            { value: 'objectMarking', label: t_i18n('Object Marking') },
          ];
        case 'objectLabel':
          return [
            { value: 'objectLabel', label: t_i18n('Object Label') },
          ];
        default:
          return [];
      }
    };

    const availableAttributes = getAvailableAttributesForType(field.type);

    return (
      <Box key={field.id} className={classes.fieldGroup}>
        <div className={classes.fieldHeader}>
          <Typography className={classes.fieldTitle}>
            {field.label || t_i18n('New Field')}
          </Typography>
          <IconButton
            size="small"
            onClick={() => {
              const updatedRelationships = [...formData.relationships];
              updatedRelationships[relationshipIndex].fields = updatedRelationships[relationshipIndex].fields?.filter((_field, i) => i !== index);
              updateFormData((prev) => ({ ...prev, relationships: updatedRelationships }));
            }}
          >
            <DeleteOutlined color="primary" />
          </IconButton>
        </div>

        <TextField
          fullWidth
          variant="standard"
          label={t_i18n('Label')}
          value={field.label}
          onChange={(e) => {
            const label = e.target.value;
            // Auto-generate name from label
            const name = label.toLowerCase().replace(/\s+/g, '_').replace(/[^a-z0-9_]/g, '');
            handleFieldChange(`${fieldPath}.label`, label);
            handleFieldChange(`${fieldPath}.name`, name || field.id);
          }}
          style={{ marginTop: 20 }}
        />

        <FormControl fullWidth variant="standard" style={{ marginTop: 20 }}>
          <InputLabel>{t_i18n('Field Type')}</InputLabel>
          <Select
            value={field.type}
            onChange={(e) => {
              handleFieldChange(`${fieldPath}.type`, e.target.value);
              // Reset attribute mapping when field type changes
              handleFieldChange(`${fieldPath}.attributeMapping.attributeName`, '');
            }}
            label={t_i18n('Field Type')}
          >
            {availableFieldTypes.map((type) => (
              <MenuItem key={type.value} value={type.value}>
                {type.label}
              </MenuItem>
            ))}
          </Select>
        </FormControl>

        <FormControl fullWidth variant="standard" style={{ marginTop: 20 }}>
          <InputLabel>{t_i18n('Map to attribute')}</InputLabel>
          <Select
            value={field.attributeMapping.attributeName}
            onChange={(e) => handleFieldChange(`${fieldPath}.attributeMapping.attributeName`, e.target.value)}
            label={t_i18n('Map to attribute')}
          >
            {availableAttributes.map((attr) => (
              <MenuItem key={attr.value} value={attr.value}>
                {attr.label}
              </MenuItem>
            ))}
          </Select>
        </FormControl>

        <FormControlLabel
          control={(
            <Switch
              checked={field.required}
              onChange={(e) => handleFieldChange(`${fieldPath}.required`, e.target.checked)}
            />
          )}
          label={t_i18n('Required')}
          style={{ marginTop: 20 }}
        />
      </Box>
    );
  };

  const renderField = (field: FormFieldAttribute, index: number, entityType: string) => {
    const fieldIndex = formData.fields.findIndex((f) => f.id === field.id);

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
      <Box key={field.id} className={classes.fieldGroup}>
        <div className={classes.fieldHeader}>
          <Typography className={classes.fieldTitle}>
            {field.isMandatory ? `${t_i18n('Field')} ${index + 1} (${t_i18n('Mandatory')})` : `${t_i18n('Field')} ${index + 1}`}
          </Typography>
          {(!field.isMandatory || isInParsedMode) && (
            <IconButton
              size="small"
              onClick={() => handleRemoveField(field.id)}
            >
              <DeleteOutlined fontSize="small" color="primary" />
            </IconButton>
          )}
        </div>

        <FormControl fullWidth variant="standard" style={{ marginTop: 20 }} disabled={field.isMandatory && !isInParsedMode}>
          <InputLabel>{t_i18n('Map to attribute')}</InputLabel>
          <Select
            value={field.attributeMapping.attributeName}
            onChange={(e) => {
              const attributeName = e.target.value;
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
            label={t_i18n('Map to attribute')}
          >
            {allAttributes.map((attr) => (
              <MenuItem key={attr.value} value={attr.value}>
                {attr.label || t_i18n(attr.name)}
              </MenuItem>
            ))}
          </Select>
        </FormControl>

        <FormControl
          fullWidth
          variant="standard"
          style={{ marginTop: 20 }}
          disabled={!field.attributeMapping.attributeName}
        >
          <InputLabel>{t_i18n('Field Type')}</InputLabel>
          <Select
            value={field.type}
            onChange={(e) => {
              handleFieldChange(`fields.${fieldIndex}.type`, e.target.value);
            }}
            label={t_i18n('Field Type')}
          >
            {availableFieldTypes.map((type) => (
              <MenuItem key={type.value} value={type.value}>
                {type.label}
              </MenuItem>
            ))}
          </Select>
        </FormControl>

        <TextField
          variant="standard"
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
          style={{ marginTop: 20 }}
        />

        {(field.type === 'select' || field.type === 'multiselect') && (() => {
          // Check if the mapped attribute has vocabulary (defaultValues)
          const entityForVocab = entityTypes.find((e) => e.value === entityType);
          const attribute = entityForVocab?.attributes?.find((attr) => attr.name === field.attributeMapping.attributeName);
          const hasVocabulary = attribute?.defaultValues && attribute.defaultValues.length > 0;

          if (hasVocabulary) {
            // Use vocabulary from the attribute
            return (
              <div style={{ marginTop: 20 }}>
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
            <div style={{ marginTop: 20 }}>
              <Typography variant="caption">{t_i18n('Options')}</Typography>
              {field.options?.map((option, optIndex) => (
                <Box key={optIndex} display="flex" alignItems="center" style={{ marginTop: 10 }}>
                  <TextField
                    variant="standard"
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
                    variant="standard"
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
                    size="small"
                    onClick={() => {
                      const newOptions = field.options?.filter((_, i) => i !== optIndex) || [];
                      handleFieldChange(`fields.${fieldIndex}.options`, newOptions);
                    }}
                  >
                    <DeleteOutlined fontSize="small" color="primary" />
                  </IconButton>
                </Box>
              ))}
              <Button
                variant="secondary"
                size="small"
                startIcon={<Add />}
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
            variant="standard"
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
            style={{ marginTop: 20 }}
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
          <FormControl fullWidth variant="standard" style={{ marginTop: 20 }}>
            <InputLabel>{t_i18n('Default value')}</InputLabel>
            <Select
              value={(() => {
                if (field.defaultValue === true) return 'true';
                if (field.defaultValue === false) return 'false';
                return 'none';
              })()}
              onChange={(e) => {
                const val = e.target.value;
                if (val === 'true') {
                  handleFieldChange(`fields.${fieldIndex}.defaultValue`, true);
                } else if (val === 'false') {
                  handleFieldChange(`fields.${fieldIndex}.defaultValue`, false);
                } else {
                  handleFieldChange(`fields.${fieldIndex}.defaultValue`, null);
                }
              }}
              label={t_i18n('Default value')}
            >
              <MenuItem value="none">{t_i18n('No default')}</MenuItem>
              <MenuItem value="true">{t_i18n('Default checked (true)')}</MenuItem>
              <MenuItem value="false">{t_i18n('Default unchecked (false)')}</MenuItem>
            </Select>
          </FormControl>
        )}

        <FormControl fullWidth variant="standard" style={{ marginTop: 20 }}>
          <InputLabel>{t_i18n('Field Width')}</InputLabel>
          <Select
            value={field.width || 'full'}
            onChange={(e) => handleFieldChange(`fields.${fieldIndex}.width`, e.target.value)}
            label={t_i18n('Field Width')}
          >
            <MenuItem value="full">{t_i18n('Full width')}</MenuItem>
            <MenuItem value="half">{t_i18n('Half width')}</MenuItem>
            <MenuItem value="third">{t_i18n('Third width')}</MenuItem>
          </Select>
        </FormControl>

        <FormControlLabel
          control={(
            <Switch
              checked={field.required}
              onChange={(e) => handleFieldChange(`fields.${fieldIndex}.required`, e.target.checked)}
              disabled={field.isMandatory && !isInParsedMode}
            />
          )}
          label={t_i18n('Required')}
          style={{ marginTop: 20 }}
        />
      </Box>
    );
  };

  const renderAdditionalEntity = (entity: AdditionalEntity, index: number) => {
    const entityIndex = formData.additionalEntities.findIndex((e) => e.id === entity.id);
    const entityFields = fieldsByEntity[entity.id] || [];
    // Display label if provided, otherwise show "Additional Entity X"
    const displayLabel = entity.label || `${t_i18n('Additional Entity')} ${index + 1}`;

    return (
      <Box key={entity.id} className={classes.entitySection}>
        <div className={classes.entityHeader}>
          <Typography variant="h6">
            {displayLabel}
          </Typography>
          <IconButton
            size="small"
            onClick={() => handleRemoveAdditionalEntity(entity.id)}
            style={{ alignSelf: 'flex-start' }}
          >
            <DeleteOutlined color="primary" />
          </IconButton>
        </div>

        <FormControl fullWidth variant="standard" style={{ marginTop: 20 }}>
          <InputLabel>{t_i18n('Entity Type')}</InputLabel>
          <Select
            value={entity.entityType}
            onChange={(e) => {
              const newEntityType = e.target.value;
              handleFieldChange(`additionalEntities.${entityIndex}.entityType`, newEntityType);
              updateFormData((prev) => {
                // Don't add mandatory fields if entity is in parsed mode
                const currentEntity = prev.additionalEntities.find((ent) => ent.id === entity.id);
                const shouldAddMandatoryFields = currentEntity?.fieldMode !== 'parsed';

                const newMandatoryFields = shouldAddMandatoryFields
                  ? getInitialMandatoryFields(newEntityType, entityTypes, t_i18n)
                      .map((field) => ({
                        ...field,
                        attributeMapping: {
                          ...field.attributeMapping,
                          entity: entity.id,
                          mappingType: 'nested' as const,
                        },
                      }))
                  : [];

                // Remove old fields for this entity and add new mandatory fields
                const fieldsWithoutEntity = prev.fields.filter((f) => f.attributeMapping.entity !== entity.id);
                return {
                  ...prev,
                  fields: [...fieldsWithoutEntity, ...newMandatoryFields],
                };
              });
            }}
            label={t_i18n('Entity Type')}
          >
            {entityTypes.map((type) => (
              <MenuItem key={type.value} value={type.value}>
                {type.label}
              </MenuItem>
            ))}
          </Select>
        </FormControl>

        <TextField
          variant="standard"
          label={t_i18n('Label for entities')}
          fullWidth
          value={entity.label}
          onChange={(e) => handleFieldChange(`additionalEntities.${entityIndex}.label`, e.target.value)}
          style={{ marginTop: 20 }}
        />

        <FormControlLabel
          control={(
            <Switch
              checked={entity.lookup}
              onChange={(e) => handleFieldChange(`additionalEntities.${entityIndex}.lookup`, e.target.checked)}
            />
          )}
          label={t_i18n('Entity lookup (select existing entities)')}
          style={{ marginTop: 20, display: 'block' }}
        />

        <FormControlLabel
          control={(
            <Switch
              checked={entity.multiple}
              onChange={(e) => handleFieldChange(`additionalEntities.${entityIndex}.multiple`, e.target.checked)}
            />
          )}
          label={t_i18n('Allow multiple instances')}
          style={{ marginTop: 20, display: 'block' }}
        />

        {entity.multiple ? (
          <TextField
            variant="standard"
            label={t_i18n('Minimum amount (0 for optional)')}
            type="number"
            fullWidth
            value={entity.minAmount || 0}
            onChange={(e) => {
              const value = parseInt(e.target.value, 10) || 0;
              handleFieldChange(`additionalEntities.${entityIndex}.minAmount`, value);
            }}
            inputProps={{ min: 0 }}
            helperText={t_i18n('Minimum number of instances required (0 means optional)')}
            style={{ marginTop: 20 }}
          />
        ) : (() => {
          // Check if this entity has any fields with default values
          const entityHasDefaultValues = entityFields.some((field) => {
            return field.defaultValue !== null && field.defaultValue !== undefined && field.defaultValue !== '';
          });

          return (
            <FormControlLabel
              control={(
                <Switch
                  checked={entity.required || false}
                  onChange={(e) => handleFieldChange(`additionalEntities.${entityIndex}.required`, e.target.checked)}
                  disabled={entityHasDefaultValues}
                />
              )}
              label={entityHasDefaultValues
                ? t_i18n('Required (auto-set due to default values)')
                : t_i18n('Required')}
              style={{ marginTop: 20, display: 'block' }}
            />
          );
        })()}

        {entity.multiple && !entity.lookup && (
          <FormControl fullWidth variant="standard" style={{ marginTop: 20 }}>
            <InputLabel>{t_i18n('Multiple Mode')}</InputLabel>
            <Select
              value={entity.fieldMode}
              onChange={(e) => handleFieldChange(`additionalEntities.${entityIndex}.fieldMode`, e.target.value)}
              label={t_i18n('Multiple Mode')}
            >
              <MenuItem value="multiple">{t_i18n('Multiple fields')}</MenuItem>
              <MenuItem value="parsed">{t_i18n('Parsed values')}</MenuItem>
            </Select>
          </FormControl>
        )}

        {entity.multiple && entity.fieldMode === 'parsed' && !entity.lookup && (
          <>
            <FormControl fullWidth variant="standard" style={{ marginTop: 20 }}>
              <InputLabel>{t_i18n('Parse Field Type')}</InputLabel>
              <Select
                value={entity.parseField}
                onChange={(e) => handleFieldChange(`additionalEntities.${entityIndex}.parseField`, e.target.value)}
                label={t_i18n('Parse Field Type')}
              >
                <MenuItem value="text">{t_i18n('Text')}</MenuItem>
                <MenuItem value="textarea">{t_i18n('Text Area')}</MenuItem>
              </Select>
            </FormControl>
            <FormControl fullWidth variant="standard" style={{ marginTop: 20 }}>
              <InputLabel>{t_i18n('Parse Mode')}</InputLabel>
              <Select
                value={entity.parseMode}
                onChange={(e) => handleFieldChange(`additionalEntities.${entityIndex}.parseMode`, e.target.value)}
                label={t_i18n('Parse Mode')}
              >
                <MenuItem value="comma">{t_i18n('Comma-separated')}</MenuItem>
                {entity.parseField === 'textarea' && (
                  <MenuItem value="line">{t_i18n('One per line')}</MenuItem>
                )}
              </Select>
            </FormControl>
            <FormControl fullWidth variant="standard" style={{ marginTop: 20 }}>
              <InputLabel>{t_i18n('Map parsed values to attribute')}</InputLabel>
              <Select
                value={entity.parseFieldMapping || ''}
                onChange={(e) => {
                  const newMapping = e.target.value;
                  updateFormData((prev) => {
                    const currentEntity = prev.additionalEntities[entityIndex];
                    const wasFirstSelection = !currentEntity.parseFieldMapping;
                    let updatedFields = prev.fields;

                    if (newMapping) {
                      if (wasFirstSelection) {
                        // First time selecting: remove ALL pre-provisioned fields for this entity
                        updatedFields = prev.fields.filter((f) => f.attributeMapping.entity !== entity.id);
                      } else {
                        // Changing selection: remove any field that maps to the newly selected attribute
                        updatedFields = prev.fields.filter((f) => !(f.attributeMapping.entity === entity.id && f.attributeMapping.attributeName === newMapping));
                      }
                    }

                    // Update the entity's parseFieldMapping
                    const updatedEntities = [...prev.additionalEntities];
                    updatedEntities[entityIndex] = {
                      ...currentEntity,
                      parseFieldMapping: newMapping,
                    };

                    return {
                      ...prev,
                      additionalEntities: updatedEntities,
                      fields: updatedFields,
                    };
                  });
                }}
                label={t_i18n('Map parsed values to attribute')}
              >
                {(() => {
                  const entityTypeSettings = entitySettings?.edges.find((e) => e.node.target_type === entity.entityType);
                  const availableAttributes = entityTypeSettings?.node.attributesDefinitions
                    ?.filter((attr) => attr.type === 'string' && attr.upsert === true)
                    .map((attr) => ({
                      value: attr.name,
                      label: attr.label || attr.name,
                    })) || [];
                  return availableAttributes.map((attr) => (
                    <MenuItem key={attr.value} value={attr.value}>
                      {attr.label}
                    </MenuItem>
                  ));
                })()}
              </Select>
            </FormControl>

            {/* Show auto-convert to STIX pattern toggle for Indicator type */}
            {entity.entityType === 'Indicator' && (
              <FormControlLabel
                control={(
                  <Switch
                    checked={entity.autoConvertToStixPattern || false}
                    onChange={() => handleFieldChange(`additionalEntities.${entityIndex}.autoConvertToStixPattern`, !entity.autoConvertToStixPattern)}
                  />
                )}
                label={t_i18n('Automatically convert to STIX patterns')}
                style={{ marginTop: 20 }}
              />
            )}
          </>
        )}

        {!entity.lookup && entity.fieldMode !== 'parsed' && (
          <>
            <Typography variant="subtitle1" style={{ marginTop: 20, marginBottom: 10 }}>
              {t_i18n('Fields')}
            </Typography>
            {entityFields.map((field, idx) => renderField(field, idx, entity.entityType))}
            <Button
              variant="secondary"
              startIcon={<Add />}
              onClick={() => handleAddField(entity.id, entity.entityType)}
              className={classes.addButton}
            >
              {t_i18n('Add field')}
            </Button>
          </>
        )}

        {!entity.lookup && entity.fieldMode === 'parsed' && entity.parseFieldMapping && (
          <>
            <Typography variant="subtitle1" style={{ marginTop: 20, marginBottom: 10 }}>
              {t_i18n('Additional Fields (will be applied to all created entities)')}
            </Typography>
            {entityFields
              .filter((field) => field.attributeMapping.attributeName !== entity.parseFieldMapping)
              .map((field, idx) => renderField(field, idx, entity.entityType))}
            <Button
              variant="secondary"
              startIcon={<Add />}
              onClick={() => handleAddField(entity.id, entity.entityType)}
              className={classes.addButton}
            >
              {t_i18n('Add field')}
            </Button>
          </>
        )}
      </Box>
    );
  };

  const renderRelationship = (relationship: EntityRelationship, index: number) => {
    const relationshipIndex = formData.relationships.findIndex((r) => r.id === relationship.id);

    const entityOptions = [
      { value: 'main_entity', label: t_i18n('Main Entity') },
      ...formData.additionalEntities.map((e, idx) => ({
        value: e.id,
        label: e.label || `${t_i18n('Additional Entity')} ${idx + 1}`,
      })),
    ];

    // Determine which entity types are selected
    const fromEntityType = relationship.fromEntity === 'main_entity'
      ? formData.mainEntityType
      : formData.additionalEntities.find((e) => e.id === relationship.fromEntity)?.entityType;

    const toEntityType = relationship.toEntity === 'main_entity'
      ? formData.mainEntityType
      : formData.additionalEntities.find((e) => e.id === relationship.toEntity)?.entityType;

    // Only get available relationships if both entities are selected
    let availableRelationships: RelationshipTypeOption[] = [];
    if (fromEntityType && toEntityType && schema.schemaRelationsTypesMapping) {
      // Use the existing resolveRelationsTypes function to get valid relationships
      const validRelationshipTypes = resolveRelationsTypes(
        fromEntityType,
        toEntityType,
        schema.schemaRelationsTypesMapping,
        true, // Include 'related-to'
      );

      // Convert to options format
      availableRelationships = validRelationshipTypes.map((relType: string) => ({
        value: relType,
        label: t_i18n(`relationship_${relType}`),
      }));
    }

    return (
      <Box key={relationship.id} className={classes.relationshipGroup}>
        <div className={classes.fieldHeader}>
          <Typography className={classes.fieldTitle}>
            {t_i18n('Relationship')} {index + 1}
          </Typography>
          <IconButton
            size="small"
            onClick={() => handleRemoveRelationship(relationship.id)}
          >
            <DeleteOutlined color="primary" />
          </IconButton>
        </div>

        <FormControl fullWidth variant="standard" style={{ marginTop: 20 }}>
          <InputLabel>{t_i18n('Source Entity')}</InputLabel>
          <Select
            value={relationship.fromEntity}
            onChange={(e) => {
              handleFieldChange(`relationships.${relationshipIndex}.fromEntity`, e.target.value);
              // Clear relationship type when from entity changes
              if (relationship.relationshipType) {
                handleFieldChange(`relationships.${relationshipIndex}.relationshipType`, '');
              }
            }}
            label={t_i18n('Source Entity')}
          >
            {entityOptions.map((opt) => (
              <MenuItem key={opt.value} value={opt.value}>
                {opt.label}
              </MenuItem>
            ))}
          </Select>
        </FormControl>

        <FormControl fullWidth variant="standard" style={{ marginTop: 20 }}>
          <InputLabel>{t_i18n('Target Entity')}</InputLabel>
          <Select
            value={relationship.toEntity}
            onChange={(e) => {
              handleFieldChange(`relationships.${relationshipIndex}.toEntity`, e.target.value);
              // Clear relationship type when to entity changes
              if (relationship.relationshipType) {
                handleFieldChange(`relationships.${relationshipIndex}.relationshipType`, '');
              }
            }}
            label={t_i18n('Target Entity')}
          >
            {entityOptions.map((opt) => (
              <MenuItem key={opt.value} value={opt.value}>
                {opt.label}
              </MenuItem>
            ))}
          </Select>
        </FormControl>

        <FormControl
          fullWidth
          variant="standard"
          style={{ marginTop: 20 }}
          disabled={!relationship.fromEntity || !relationship.toEntity}
        >
          <InputLabel>{t_i18n('Relationship Type')}</InputLabel>
          <Select
            value={relationship.relationshipType}
            onChange={(e) => handleFieldChange(`relationships.${relationshipIndex}.relationshipType`, e.target.value)}
            label={t_i18n('Relationship Type')}
            disabled={!relationship.fromEntity || !relationship.toEntity}
          >
            {availableRelationships.map((rel) => (
              <MenuItem key={rel.value} value={rel.value}>
                {rel.label}
              </MenuItem>
            ))}
          </Select>
        </FormControl>

        <FormControlLabel
          control={(
            <Switch
              checked={relationship.required || false}
              onChange={(e) => handleFieldChange(`relationships.${relationshipIndex}.required`, e.target.checked)}
            />
          )}
          label={t_i18n('Required')}
          style={{ marginTop: 20 }}
        />

        {/* Additional fields for relationship */}
        {relationship.relationshipType && (
          <>
            <Typography variant="subtitle1" style={{ marginTop: 20, marginBottom: 10 }}>
              {t_i18n('Additional Fields')}
            </Typography>
            {(relationship.fields || []).map((field, fieldIdx) => renderRelationshipField(
              field,
              fieldIdx,
              relationshipIndex,
            ))}
            <Button
              variant="secondary"
              startIcon={<Add />}
              onClick={() => {
                const fieldId = generateFieldId();
                const newField: FormFieldAttribute = {
                  id: fieldId,
                  name: `field_${fieldId.slice(0, 8)}`,
                  label: '',
                  type: 'text',
                  required: false,
                  attributeMapping: {
                    entity: relationship.id,
                    attributeName: '',
                  },
                };
                const updatedRelationships = [...formData.relationships];
                updatedRelationships[relationshipIndex] = {
                  ...relationship,
                  fields: [...(relationship.fields || []), newField],
                };
                updateFormData((prev) => ({
                  ...prev,
                  relationships: updatedRelationships,
                }));
              }}
              className={classes.addButton}
              disabled={!relationship.relationshipType}
            >
              {t_i18n('Add field')}
            </Button>
          </>
        )}

      </Box>
    );
  };

  return (
    <div className={classes.container}>
      <Tabs value={currentTab} onChange={(_, value) => setCurrentTab(value)}>
        <Tab label={t_i18n('Main Entity')} />
        <Tab label={t_i18n('Additional Entities')} />
        {hasAdditionalEntities && <Tab label={t_i18n('Relationships')} />}
      </Tabs>

      {currentTab === 0 && (
        <div className={classes.tabPanel}>
          <FormControl fullWidth variant="standard">
            <InputLabel>{t_i18n('Main Entity Type')}</InputLabel>
            <Select
              value={formData.mainEntityType}
              onChange={(e) => handleMainEntityTypeChange(e.target.value)}
              label={t_i18n('Main Entity Type')}
            >
              {entityTypes.map((type) => (
                <MenuItem key={type.value} value={type.value}>
                  {type.label}
                </MenuItem>
              ))}
            </Select>
          </FormControl>

          <FormControlLabel
            control={(
              <Switch
                checked={formData.mainEntityMultiple}
                onChange={(e) => handleFieldChange('mainEntityMultiple', e.target.checked)}
              />
            )}
            label={t_i18n('Allow multiple instances of main entity')}
            style={{ marginTop: 20, display: 'block' }}
          />

          <FormControlLabel
            control={(
              <Switch
                checked={formData.mainEntityLookup}
                onChange={(e) => handleFieldChange('mainEntityLookup', e.target.checked)}
              />
            )}
            label={t_i18n('Entity lookup (select existing entities)')}
            style={{ marginTop: 20, display: 'block' }}
          />

          {isContainer && (
            <FormControlLabel
              control={(
                <Switch
                  checked={formData.includeInContainer}
                  onChange={(e) => handleFieldChange('includeInContainer', e.target.checked)}
                />
              )}
              label={t_i18n('Include entities in container')}
              style={{ marginTop: 20, display: 'block' }}
            />
          )}

          <FormControlLabel
            control={(
              <Switch
                checked={formData.isDraftByDefault}
                onChange={(e) => handleFieldChange('isDraftByDefault', e.target.checked)}
              />
            )}
            label={t_i18n('Create as draft by default')}
            style={{ marginTop: 20, display: 'block' }}
          />

          {formData.isDraftByDefault && (
            <FormControlLabel
              control={(
                <Switch
                  checked={formData.allowDraftOverride}
                  onChange={(e) => handleFieldChange('allowDraftOverride', e.target.checked)}
                />
              )}
              label={t_i18n('Allow users to uncheck draft mode')}
              style={{ marginTop: 20, display: 'block' }}
            />
          )}

          {formData.mainEntityMultiple && !formData.mainEntityLookup && (
            <FormControl fullWidth variant="standard" style={{ marginTop: 20 }}>
              <InputLabel>{t_i18n('Multiple Mode')}</InputLabel>
              <Select
                value={formData.mainEntityFieldMode}
                onChange={(e) => handleFieldChange('mainEntityFieldMode', e.target.value)}
                label={t_i18n('Multiple Mode')}
              >
                <MenuItem value="multiple">{t_i18n('Multiple fields')}</MenuItem>
                <MenuItem value="parsed">{t_i18n('Parsed values')}</MenuItem>
              </Select>
            </FormControl>
          )}

          {formData.mainEntityMultiple && formData.mainEntityFieldMode === 'parsed' && !formData.mainEntityLookup && (
            <>
              <FormControl fullWidth variant="standard" style={{ marginTop: 20 }}>
                <InputLabel>{t_i18n('Parse Field Type')}</InputLabel>
                <Select
                  value={formData.mainEntityParseField}
                  onChange={(e) => handleFieldChange('mainEntityParseField', e.target.value)}
                  label={t_i18n('Parse Field Type')}
                >
                  <MenuItem value="text">{t_i18n('Text')}</MenuItem>
                  <MenuItem value="textarea">{t_i18n('Text Area')}</MenuItem>
                </Select>
              </FormControl>
              <FormControl fullWidth variant="standard" style={{ marginTop: 20 }}>
                <InputLabel>{t_i18n('Parse Mode')}</InputLabel>
                <Select
                  value={formData.mainEntityParseMode}
                  onChange={(e) => handleFieldChange('mainEntityParseMode', e.target.value)}
                  label={t_i18n('Parse Mode')}
                >
                  <MenuItem value="comma">{t_i18n('Comma-separated')}</MenuItem>
                  {formData.mainEntityParseField === 'textarea' && (
                    <MenuItem value="line">{t_i18n('One per line')}</MenuItem>
                  )}
                </Select>
              </FormControl>
              <FormControl fullWidth variant="standard" style={{ marginTop: 20 }}>
                <InputLabel>{t_i18n('Map parsed values to attribute')}</InputLabel>
                <Select
                  value={formData.mainEntityParseFieldMapping || ''}
                  onChange={(e) => {
                    const newMapping = e.target.value;
                    updateFormData((prev) => {
                      const wasFirstSelection = !prev.mainEntityParseFieldMapping;
                      let updatedFields = prev.fields;

                      if (newMapping) {
                        if (wasFirstSelection) {
                          // First time selecting: remove ALL pre-provisioned fields for main entity
                          updatedFields = prev.fields.filter((f) => f.attributeMapping.entity !== 'main_entity');
                        } else {
                          // Changing selection: remove any field that maps to the newly selected attribute
                          updatedFields = prev.fields.filter((f) => !(f.attributeMapping.entity === 'main_entity' && f.attributeMapping.attributeName === newMapping));
                        }
                      }

                      return {
                        ...prev,
                        mainEntityParseFieldMapping: newMapping,
                        fields: updatedFields,
                      };
                    });
                  }}
                  label={t_i18n('Map parsed values to attribute')}
                >
                  {(() => {
                    const { mainEntityType } = formData;
                    const entityTypeSettings = entitySettings?.edges.find((e) => e.node.target_type === mainEntityType);
                    const availableAttributes = entityTypeSettings?.node.attributesDefinitions
                      ?.filter((attr) => attr.type === 'string' && attr.upsert === true)
                      .map((attr) => ({
                        value: attr.name,
                        label: attr.label || attr.name,
                      })) || [];
                    return availableAttributes.map((attr) => (
                      <MenuItem key={attr.value} value={attr.value}>
                        {attr.label}
                      </MenuItem>
                    ));
                  })()}
                </Select>
              </FormControl>

              {/* Show auto-convert to STIX pattern toggle for Indicator type */}
              {formData.mainEntityType === 'Indicator' && (
                <>
                  <FormControlLabel
                    control={(
                      <Switch
                        checked={formData.mainEntityAutoConvertToStixPattern || false}
                        onChange={() => handleFieldChange('mainEntityAutoConvertToStixPattern', !formData.mainEntityAutoConvertToStixPattern)}
                      />
                    )}
                    label={t_i18n('Automatically convert to STIX patterns')}
                    style={{ marginTop: 20 }}
                  />
                  <FormControlLabel
                    control={(
                      <Switch
                        checked={formData.autoCreateObservableFromIndicator || false}
                        onChange={() => handleFieldChange('autoCreateObservableFromIndicator', !formData.autoCreateObservableFromIndicator)}
                      />
                    )}
                    label={t_i18n('Automatically create observables from indicators')}
                    style={{ marginTop: 10 }}
                  />
                </>
              )}

              {/* Show auto-create indicator toggle for Observable types */}
              {['Artifact', 'Autonomous-System', 'Directory', 'Domain-Name', 'Email-Addr', 'Email-Message',
                'Email-Mime-Part-Type', 'File', 'IPv4-Addr', 'IPv6-Addr', 'Mac-Addr', 'Mutex', 'Network-Traffic',
                'Process', 'Software', 'Url', 'User-Account', 'Windows-Registry-Key', 'Windows-Registry-Value-Type',
                'X509-Certificate', 'Cryptocurrency-Wallet', 'Hostname', 'Text', 'User-Agent', 'Bank-Account',
                'Phone-Number', 'Payment-Card', 'Media-Content',
              ].includes(formData.mainEntityType) && (
                <FormControlLabel
                  control={(
                    <Switch
                      checked={formData.autoCreateIndicatorFromObservable || false}
                      onChange={() => handleFieldChange('autoCreateIndicatorFromObservable', !formData.autoCreateIndicatorFromObservable)}
                    />
                  )}
                  label={t_i18n('Automatically create indicators from observables')}
                  style={{ marginTop: 20 }}
                />
              )}
            </>
          )}

          {(() => {
            if (formData.mainEntityLookup) {
              return (
                <Alert severity="info" className={classes.alert} style={{ marginTop: 20 }}>
                  {t_i18n('Entity lookup enabled. Users will select existing entities of this type.')}
                </Alert>
              );
            }
            if (formData.mainEntityFieldMode === 'parsed' && formData.mainEntityMultiple) {
              return (
                <>
                  <Alert severity="info" className={classes.alert} style={{ marginTop: 20 }}>
                    {t_i18n('Parsed mode enabled. Users can enter multiple values in a single field. Additional fields can be defined that will apply to all created entities.')}
                  </Alert>
                  {formData.mainEntityParseFieldMapping && (
                    <div style={{ marginTop: 20 }}>
                      <Typography variant="h6" gutterBottom>
                        {t_i18n('Additional Fields (will be applied to all created entities)')}
                      </Typography>
                      {(fieldsByEntity.main_entity || [])
                        .filter((field) => field.attributeMapping.attributeName !== formData.mainEntityParseFieldMapping)
                        .map((field, idx) => renderField(field, idx, formData.mainEntityType))}
                      <Button
                        variant="secondary"
                        startIcon={<Add />}
                        onClick={() => handleAddField('main_entity', formData.mainEntityType)}
                        className={classes.addButton}
                      >
                        {t_i18n('Add field')}
                      </Button>
                    </div>
                  )}
                </>
              );
            }
            return (
              <div style={{ marginTop: 20 }}>
                <Typography variant="h6" gutterBottom>
                  {t_i18n('Main Entity Fields')}
                </Typography>
                {(fieldsByEntity.main_entity || []).map((field, idx) => renderField(field, idx, formData.mainEntityType))}
                <Button
                  variant="secondary"
                  startIcon={<Add />}
                  onClick={() => handleAddField('main_entity', formData.mainEntityType)}
                  className={classes.addButton}
                >
                  {t_i18n('Add field')}
                </Button>
              </div>
            );
          })()}
        </div>
      )}

      {currentTab === 1 && (
        <div className={classes.tabPanel}>
          {formData.additionalEntities.map((entity, idx) => renderAdditionalEntity(entity, idx))}
          <Button
            variant="secondary"
            startIcon={<AddCircleOutlined />}
            onClick={handleAddAdditionalEntity}
            className={classes.addButton}
          >
            {t_i18n('Add additional entity')}
          </Button>
        </div>
      )}

      {currentTab === 2 && hasAdditionalEntities && (
        <div className={classes.tabPanel}>
          <Typography variant="h6" gutterBottom>
            {t_i18n('Relationships')}
          </Typography>
          {formData.relationships.map((relationship, idx) => renderRelationship(relationship, idx))}
          <Button
            variant="secondary"
            startIcon={<Add />}
            onClick={handleAddRelationship}
            className={classes.addButton}
          >
            {t_i18n('Add relationship')}
          </Button>
        </div>
      )}
    </div>
  );
};

export default FormSchemaEditor;
