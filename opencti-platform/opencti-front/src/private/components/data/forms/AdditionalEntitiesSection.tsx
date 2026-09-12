import Button from '@common/button/Button';
import { Add, DeleteOutlined } from '@mui/icons-material';
// fds:keep-mui Switch/TextField predate this PR; entity form fields still use MUI here.
import { FormControlLabel, Stack, Switch, TextField, Typography } from '@mui/material';
import { IconButton, Input, Select, SelectContent, SelectItem, SelectLabel, SelectTrigger, SelectValue } from '@filigran/design-system';
import React from 'react';
import { useFormatter } from '../../../../components/i18n';
import type { AdditionalEntity, EntitySettings, EntityTypeOption, FormBuilderData, FormFieldAttribute } from './Form.d';
import { getInitialMandatoryFields } from './FormUtils';

export interface AdditionalEntitiesSectionProps {
  formData: FormBuilderData;
  handleFieldChange: (path: string, value: unknown) => void;
  updateFormData: (updater: (prev: FormBuilderData) => FormBuilderData) => void;
  entityTypes: EntityTypeOption[];
  fieldsByEntity: Record<string, FormFieldAttribute[]>;
  handleRemoveAdditionalEntity: (entityId: string) => void;
  entitySettings: EntitySettings;
  renderField: (field: FormFieldAttribute, index: number, entityType: string, entityFields: FormFieldAttribute[]) => React.ReactNode;
  handleAddField: (entityId: string, entityType: string) => void;
  handleAddAdditionalEntity: () => void;
  tabPanelClassName: string;
  entitySectionClassName: string;
  entityHeaderClassName: string;
  addButtonClassName: string;
}

const AdditionalEntitiesSection: React.FC<AdditionalEntitiesSectionProps> = ({
  formData,
  handleFieldChange,
  updateFormData,
  entityTypes,
  fieldsByEntity,
  handleRemoveAdditionalEntity,
  entitySettings,
  renderField,
  handleAddField,
  handleAddAdditionalEntity,
  tabPanelClassName,
  entitySectionClassName,
  entityHeaderClassName,
  addButtonClassName,
}) => {
  const { t_i18n } = useFormatter();

  const renderAdditionalEntity = (entity: AdditionalEntity, index: number) => {
    const entityIndex = formData.additionalEntities.findIndex((e) => e.id === entity.id);
    const entityFields = fieldsByEntity[entity.id] || [];
    // Display label if provided, otherwise show "Additional Entity X"
    const displayLabel = entity.label || `${t_i18n('Additional Entity')} ${index + 1}`;

    return (
      <Stack key={entity.id} className={entitySectionClassName} gap={2}>
        <div className={entityHeaderClassName}>
          <Typography variant="h6">
            {displayLabel}
          </Typography>
          <IconButton
            variant="destructive"
            priority="tertiary"
            aria-label={t_i18n('Remove')}
            size="sm"
            onClick={() => handleRemoveAdditionalEntity(entity.id)}
            className="self-start"
            icon={<DeleteOutlined />}
          />
        </div>

        <Select
          value={entity.entityType}
          onValueChange={(value) => {
            const newEntityType = value;
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
        >
          <div>
            <SelectLabel>{t_i18n('Entity Type')}</SelectLabel>
            <SelectTrigger className="w-full">
              <SelectValue />
            </SelectTrigger>
            <SelectContent aria-label={t_i18n('Entity Type')}>
              {entityTypes.map((type) => (
                <SelectItem key={type.value} value={type.value}>
                  {type.label}
                </SelectItem>
              ))}
            </SelectContent>
          </div>
        </Select>

        <TextField
          variant="outlined"
          label={t_i18n('Label for entities')}
          fullWidth
          value={entity.label}
          onChange={(e) => handleFieldChange(`additionalEntities.${entityIndex}.label`, e.target.value)}
        />

        <FormControlLabel
          control={(
            <Switch
              checked={entity.lookup}
              onChange={(e) => handleFieldChange(`additionalEntities.${entityIndex}.lookup`, e.target.checked)}
            />
          )}
          label={t_i18n('Entity lookup (select existing entities)')}
        />

        {entity.lookup && (
          <FormControlLabel
            control={(
              <Switch
                checked={entity.disableCreation || false}
                onChange={(e) => handleFieldChange(`additionalEntities.${entityIndex}.disableCreation`, e.target.checked)}
              />
            )}
            label={t_i18n('Disable on-the-fly entity creation')}
            style={{ marginLeft: 20, display: 'block' }}
          />
        )}

        <FormControlLabel
          control={(
            <Switch
              checked={entity.multiple}
              onChange={(e) => handleFieldChange(`additionalEntities.${entityIndex}.multiple`, e.target.checked)}
            />
          )}
          label={t_i18n('Allow multiple instances')}
        />

        {entity.multiple ? (
          <Input
            label={t_i18n('Minimum amount (0 for optional)')}
            type="number"
            min={0}
            value={String(entity.minAmount ?? 0)}
            onChange={(e) => {
              const value = parseInt(e.target.value, 10) || 0;
              handleFieldChange(`additionalEntities.${entityIndex}.minAmount`, value);
            }}
            helperText={t_i18n('Minimum number of instances required (0 means optional)')}
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
            />
          );
        })()}

        {entity.multiple && !entity.lookup && (
          <Select
            value={entity.fieldMode}
            onValueChange={(value) => handleFieldChange(`additionalEntities.${entityIndex}.fieldMode`, value)}
          >
            <div>
              <SelectLabel>{t_i18n('Multiple Mode')}</SelectLabel>
              <SelectTrigger className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent aria-label={t_i18n('Multiple Mode')}>
                <SelectItem value="multiple">{t_i18n('Multiple fields')}</SelectItem>
                <SelectItem value="parsed">{t_i18n('Parsed values')}</SelectItem>
              </SelectContent>
            </div>
          </Select>
        )}

        {entity.multiple && entity.fieldMode === 'parsed' && !entity.lookup && (
          <>
            <Select
              value={entity.parseField}
              onValueChange={(value) => handleFieldChange(`additionalEntities.${entityIndex}.parseField`, value)}
            >
              <div>
                <SelectLabel>{t_i18n('Parse Field Type')}</SelectLabel>
                <SelectTrigger className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent aria-label={t_i18n('Parse Field Type')}>
                  <SelectItem value="text">{t_i18n('Text')}</SelectItem>
                  <SelectItem value="textarea">{t_i18n('Text Area')}</SelectItem>
                </SelectContent>
              </div>
            </Select>

            <Select
              value={entity.parseMode}
              onValueChange={(value) => handleFieldChange(`additionalEntities.${entityIndex}.parseMode`, value)}
            >
              <div>
                <SelectLabel>{t_i18n('Parse Mode')}</SelectLabel>
                <SelectTrigger className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent aria-label={t_i18n('Parse Mode')}>
                  <SelectItem value="comma">{t_i18n('Comma-separated')}</SelectItem>
                  {entity.parseField === 'textarea' && (
                    <SelectItem value="line">{t_i18n('One per line')}</SelectItem>
                  )}
                </SelectContent>
              </div>
            </Select>

            <Select
              value={entity.parseFieldMapping || ''}
              onValueChange={(value) => {
                const newMapping = value;
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
            >
              <div>
                <SelectLabel>{t_i18n('Map parsed values to attribute')}</SelectLabel>
                <SelectTrigger className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent aria-label={t_i18n('Map parsed values to attribute')}>
                  {(() => {
                    const entityTypeSettings = entitySettings?.edges.find((e) => e.node.target_type === entity.entityType);
                    const availableAttributes = entityTypeSettings?.node.attributesDefinitions
                      ?.filter((attr) => attr.type === 'string' && attr.upsert === true)
                      .map((attr) => ({
                        value: attr.name,
                        label: attr.label || attr.name,
                      })) || [];
                    return availableAttributes.map((attr) => (
                      <SelectItem key={attr.value} value={attr.value}>
                        {attr.label}
                      </SelectItem>
                    ));
                  })()}
                </SelectContent>
              </div>
            </Select>

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
              />
            )}
          </>
        )}

        {!entity.lookup && entity.fieldMode !== 'parsed' && (
          <>
            <Typography variant="subtitle1">
              {t_i18n('Fields')}
            </Typography>
            {entityFields.map((field, idx) => renderField(field, idx, entity.entityType, entityFields))}
            <div>
              <Button
                variant="secondary"
                startIcon={<Add />}
                onClick={() => handleAddField(entity.id, entity.entityType)}
              >
                {t_i18n('Add field')}
              </Button>
            </div>
          </>
        )}

        {!entity.lookup && entity.fieldMode === 'parsed' && entity.parseFieldMapping && (
          <>
            <Typography variant="subtitle1" style={{ marginTop: 20, marginBottom: 10 }}>
              {t_i18n('Additional Fields (will be applied to all created entities)')}
            </Typography>
            {(() => {
              const parsedModeFields = entityFields.filter((field) => field.attributeMapping.attributeName !== entity.parseFieldMapping);
              return parsedModeFields.map((field, idx) => renderField(field, idx, entity.entityType, parsedModeFields));
            })()}
            <Button
              variant="secondary"
              startIcon={<Add />}
              onClick={() => handleAddField(entity.id, entity.entityType)}
              className={addButtonClassName}
            >
              {t_i18n('Add field')}
            </Button>
          </>
        )}
      </Stack>
    );
  };

  return (
    <div className={tabPanelClassName}>
      <Stack gap={1}>
        {formData.additionalEntities.map((entity, idx) => renderAdditionalEntity(entity, idx))}
        <div>
          <Button
            variant="secondary"
            startIcon={<Add />}
            onClick={handleAddAdditionalEntity}
            className={addButtonClassName}
          >
            {t_i18n('Add additional entity')}
          </Button>
        </div>
      </Stack>
    </div>
  );
};

export default AdditionalEntitiesSection;
