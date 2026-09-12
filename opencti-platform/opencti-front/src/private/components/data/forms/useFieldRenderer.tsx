import Button from '@common/button/Button';
import { Add, ArrowDownward, ArrowUpward, DeleteOutlined } from '@mui/icons-material';
// fds:keep-mui Switch/TextField predate this PR; field options/default-value inputs still use MUI here.
import { Box, FormControlLabel, Stack, Switch, TextField, Typography } from '@mui/material';
import { IconButton, Select, SelectContent, SelectItem, SelectLabel, SelectTrigger, SelectValue } from '@filigran/design-system';
import { useFormatter } from '../../../../components/i18n';
import { getVocabularyMappingByAttribute } from '../../../../utils/vocabularyMapping';
import type { EntityTypeOption, FormBuilderData, FormFieldAttribute } from './Form.d';
import { FIELD_TYPES, getAttributesForEntityType as getAttributesUtil, getAvailableFieldTypes } from './FormUtils';

interface UseFieldRendererParams {
  formData: FormBuilderData;
  entityTypes: EntityTypeOption[];
  handleFieldChange: (path: string, value: unknown) => void;
  handleMoveFieldUp: (entityId: string, fieldId: string) => void;
  handleMoveFieldDown: (entityId: string, fieldId: string) => void;
  handleRemoveField: (fieldId: string) => void;
  fieldGroupClassName: string;
  fieldHeaderClassName: string;
  fieldTitleClassName: string;
}

const useFieldRenderer = ({
  formData,
  entityTypes,
  handleFieldChange,
  handleMoveFieldUp,
  handleMoveFieldDown,
  handleRemoveField,
  fieldGroupClassName,
  fieldHeaderClassName,
  fieldTitleClassName,
}: UseFieldRendererParams) => {
  const { t_i18n } = useFormatter();

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
      <Stack key={field.id} className={fieldGroupClassName} gap={1}>
        <div className={fieldHeaderClassName}>
          <Typography className={fieldTitleClassName}>
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

  return renderField;
};

export default useFieldRenderer;
