import React, { FunctionComponent, useState, useMemo, useCallback, useEffect } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { Add, DeleteOutlined, AddCircleOutlined } from '@mui/icons-material';
import { Box, IconButton, MenuItem, Tab, Tabs, Typography, TextField, Alert, Button, Select, FormControl, InputLabel, Switch, FormControlLabel } from '@mui/material';
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
} from './FormUtils';
import { resolveRelationsTypes } from '../../../../utils/Relation';
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

  const getAttributesForEntityType = (entityType: string, fieldType: string) => {
    return getAttributesUtil(entityType, fieldType, entityTypes, t_i18n);
  };

  const handleMainEntityTypeChange = (value: string) => {
    updateFormData((prev) => {
      const newMandatoryFields = getInitialMandatoryFields(value, entityTypes, t_i18n);
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
      return newData;
    });
  };

  const handleAddField = (entityId: string, entityType: string) => {
    const fieldId = generateFieldId();
    const newField: FormFieldAttribute = {
      id: fieldId,
      name: `field_${fieldId}`, // Auto-generated name
      label: '',
      type: 'text',
      required: false,
      defaultValue: null, // Initialize default value
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

  const renderField = (field: FormFieldAttribute, index: number, entityType: string) => {
    const availableFieldTypes = getAvailableFieldTypes(entityType, entityTypes);
    const availableAttributes = field.type ? getAttributesForEntityType(entityType, field.type) : [];
    const fieldIndex = formData.fields.findIndex((f) => f.id === field.id);

    return (
      <Box key={field.id} className={classes.fieldGroup}>
        <div className={classes.fieldHeader}>
          <Typography className={classes.fieldTitle}>
            {field.isMandatory ? `${t_i18n('Field')} ${index + 1} (${t_i18n('Mandatory')})` : `${t_i18n('Field')} ${index + 1}`}
          </Typography>
          {!field.isMandatory && (
            <IconButton
              size="small"
              onClick={() => handleRemoveField(field.id)}
            >
              <DeleteOutlined fontSize="small" color="primary" />
            </IconButton>
          )}
        </div>

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

        <FormControl fullWidth variant="standard" style={{ marginTop: 20 }} disabled={field.isMandatory}>
          <InputLabel>{t_i18n('Field Type')}</InputLabel>
          <Select
            value={field.type}
            onChange={(e) => {
              handleFieldChange(`fields.${fieldIndex}.type`, e.target.value);
              handleFieldChange(`fields.${fieldIndex}.attributeMapping.attributeName`, '');
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

        <FormControl fullWidth variant="standard" style={{ marginTop: 20 }} disabled={field.isMandatory}>
          <InputLabel>{t_i18n('Map to attribute')}</InputLabel>
          <Select
            value={field.attributeMapping.attributeName}
            onChange={(e) => handleFieldChange(`fields.${fieldIndex}.attributeMapping.attributeName`, e.target.value)}
            label={t_i18n('Map to attribute')}
          >
            {availableAttributes.map((attr) => (
              <MenuItem key={attr.value} value={attr.value}>
                {attr.label}
              </MenuItem>
            ))}
          </Select>
        </FormControl>

        {(field.type === 'select' || field.type === 'multiselect') && (
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
              variant="outlined"
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
        )}

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
          <FormControlLabel
            control={
              <Switch
                checked={!!field.defaultValue}
                onChange={(e) => handleFieldChange(`fields.${fieldIndex}.defaultValue`, e.target.checked)}
              />
            }
            label={t_i18n('Default checked')}
            style={{ marginTop: 20 }}
          />
        )}

        <FormControlLabel
          control={
            <Switch
              checked={field.required}
              onChange={(e) => handleFieldChange(`fields.${fieldIndex}.required`, e.target.checked)}
              disabled={field.isMandatory}
            />
          }
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
                // Get mandatory fields for the new entity type
                const newMandatoryFields = getInitialMandatoryFields(newEntityType, entityTypes, t_i18n)
                  .map((field) => ({
                    ...field,
                    attributeMapping: {
                      ...field.attributeMapping,
                      entity: entity.id,
                      mappingType: 'nested' as const,
                    },
                  }));

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
          control={
            <Switch
              checked={entity.lookup}
              onChange={(e) => handleFieldChange(`additionalEntities.${entityIndex}.lookup`, e.target.checked)}
            />
          }
          label={t_i18n('Entity lookup (select existing entities)')}
          style={{ marginTop: 20, display: 'block' }}
        />

        <FormControlLabel
          control={
            <Switch
              checked={entity.multiple}
              onChange={(e) => handleFieldChange(`additionalEntities.${entityIndex}.multiple`, e.target.checked)}
            />
          }
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
        ) : (
          <FormControlLabel
            control={
              <Switch
                checked={entity.required || false}
                onChange={(e) => handleFieldChange(`additionalEntities.${entityIndex}.required`, e.target.checked)}
              />
            }
            label={t_i18n('Required')}
            style={{ marginTop: 20, display: 'block' }}
          />
        )}

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
                onChange={(e) => handleFieldChange(`additionalEntities.${entityIndex}.parseFieldMapping`, e.target.value)}
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
                control={
                  <Switch
                    checked={entity.autoConvertToStixPattern || false}
                    onChange={() => handleFieldChange(`additionalEntities.${entityIndex}.autoConvertToStixPattern`, !entity.autoConvertToStixPattern)}
                  />
                }
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
              variant="outlined"
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
            control={
              <Switch
                checked={formData.mainEntityMultiple}
                onChange={(e) => handleFieldChange('mainEntityMultiple', e.target.checked)}
              />
            }
            label={t_i18n('Allow multiple instances of main entity')}
            style={{ marginTop: 20, display: 'block' }}
          />

          <FormControlLabel
            control={
              <Switch
                checked={formData.mainEntityLookup}
                onChange={(e) => handleFieldChange('mainEntityLookup', e.target.checked)}
              />
            }
            label={t_i18n('Entity lookup (select existing entities)')}
            style={{ marginTop: 20, display: 'block' }}
          />

          {isContainer && (
            <FormControlLabel
              control={
                <Switch
                  checked={formData.includeInContainer}
                  onChange={(e) => handleFieldChange('includeInContainer', e.target.checked)}
                />
              }
              label={t_i18n('Include entities in container')}
              style={{ marginTop: 20, display: 'block' }}
            />
          )}

          <FormControlLabel
            control={
              <Switch
                checked={formData.isDraftByDefault}
                onChange={(e) => handleFieldChange('isDraftByDefault', e.target.checked)}
              />
            }
            label={t_i18n('Create as draft by default')}
            style={{ marginTop: 20, display: 'block' }}
          />

          {formData.isDraftByDefault && (
            <FormControlLabel
              control={
                <Switch
                  checked={formData.allowDraftOverride}
                  onChange={(e) => handleFieldChange('allowDraftOverride', e.target.checked)}
                />
              }
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
                  onChange={(e) => handleFieldChange('mainEntityParseFieldMapping', e.target.value)}
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
                <FormControlLabel
                  control={
                    <Switch
                      checked={formData.mainEntityAutoConvertToStixPattern || false}
                      onChange={() => handleFieldChange('mainEntityAutoConvertToStixPattern', !formData.mainEntityAutoConvertToStixPattern)}
                    />
                  }
                  label={t_i18n('Automatically convert to STIX patterns')}
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
                <Alert severity="info" className={classes.alert} style={{ marginTop: 20 }}>
                  {t_i18n('Parsed mode enabled. A single field will be provided to enter multiple entity names.')}
                </Alert>
              );
            }
            return (
              <div style={{ marginTop: 20 }}>
                <Typography variant="h6" gutterBottom>
                  {t_i18n('Main Entity Fields')}
                </Typography>
                {(fieldsByEntity.main_entity || []).map((field, idx) => renderField(field, idx, formData.mainEntityType))}
                <Button
                  variant="outlined"
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
            variant="outlined"
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
            variant="outlined"
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
