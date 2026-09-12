import Button from '@common/button/Button';
import { Add } from '@mui/icons-material';
import { Alert, FormControlLabel, Stack, Switch, Typography } from '@mui/material';
import { Select, SelectContent, SelectItem, SelectLabel, SelectTrigger, SelectValue } from '@filigran/design-system';
import React from 'react';
import { useFormatter } from '../../../../components/i18n';
import type { EntityTypeOption, FormBuilderData, FormFieldAttribute } from './Form.d';
import DraftDefaultsSection from './DraftDefaultsSection';
import type { FormSchemaEditorProps } from './FormSchemaEditor';

export interface MainEntitySectionProps {
  formData: FormBuilderData;
  handleFieldChange: (path: string, value: unknown) => void;
  updateFormData: (updater: (prev: FormBuilderData) => FormBuilderData) => void;
  entityTypes: EntityTypeOption[];
  handleMainEntityTypeChange: (value: string) => void;
  isContainer: boolean;
  entitySettings: FormSchemaEditorProps['entitySettings'];
  fieldsByEntity: Record<string, FormFieldAttribute[]>;
  renderField: (field: FormFieldAttribute, index: number, entityType: string, entityFields: FormFieldAttribute[]) => React.ReactNode;
  handleAddField: (entityId: string, entityType: string) => void;
  tabPanelClassName: string;
  alertClassName: string;
  addButtonClassName: string;
}

const MainEntitySection: React.FC<MainEntitySectionProps> = ({
  formData,
  handleFieldChange,
  updateFormData,
  entityTypes,
  handleMainEntityTypeChange,
  isContainer,
  entitySettings,
  fieldsByEntity,
  renderField,
  handleAddField,
  tabPanelClassName,
  alertClassName,
  addButtonClassName,
}) => {
  const { t_i18n } = useFormatter();

  return (
    <Stack gap={2} className={tabPanelClassName}>
      <Select
        value={formData.mainEntityType}
        onValueChange={(value) => handleMainEntityTypeChange(value)}
      >
        <div>
          <SelectLabel>{t_i18n('Main Entity Type')}</SelectLabel>
          <SelectTrigger className="w-full">
            <SelectValue />
          </SelectTrigger>
          <SelectContent aria-label={t_i18n('Main Entity Type')}>
            {entityTypes.map((type) => (
              <SelectItem key={type.value} value={type.value}>
                {type.label}
              </SelectItem>
            ))}
          </SelectContent>
        </div>
      </Select>

      <Stack gap={2}>
        <FormControlLabel
          control={(
            <Switch
              checked={formData.mainEntityMultiple}
              onChange={(e) => handleFieldChange('mainEntityMultiple', e.target.checked)}
            />
          )}
          label={t_i18n('Allow multiple instances of main entity')}
        />

        <FormControlLabel
          control={(
            <Switch
              checked={formData.mainEntityLookup}
              onChange={(e) => handleFieldChange('mainEntityLookup', e.target.checked)}
            />
          )}
          label={t_i18n('Entity lookup (select existing entities)')}
        />

        {formData.mainEntityLookup && (
          <FormControlLabel
            control={(
              <Switch
                checked={formData.mainEntityDisableCreation || false}
                onChange={(e) => handleFieldChange('mainEntityDisableCreation', e.target.checked)}
              />
            )}
            label={t_i18n('Disable on-the-fly entity creation')}
            style={{ marginTop: 10, marginLeft: 20, display: 'block' }}
          />
        )}

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
      </Stack>

      <DraftDefaultsSection formData={formData} handleFieldChange={handleFieldChange} />

      {formData.mainEntityMultiple && !formData.mainEntityLookup && (
        <Select
          value={formData.mainEntityFieldMode}
          onValueChange={(value) => handleFieldChange('mainEntityFieldMode', value)}
        >
          <SelectLabel>{t_i18n('Multiple Mode')}</SelectLabel>
          <SelectTrigger className="w-full">
            <SelectValue />
          </SelectTrigger>
          <SelectContent aria-label={t_i18n('Multiple Mode')}>
            <SelectItem value="multiple">{t_i18n('Multiple fields')}</SelectItem>
            <SelectItem value="parsed">{t_i18n('Parsed values')}</SelectItem>
          </SelectContent>
        </Select>
      )}

      {formData.mainEntityMultiple && formData.mainEntityFieldMode === 'parsed' && !formData.mainEntityLookup && (
        <>
          <Select
            value={formData.mainEntityParseField}
            onValueChange={(value) => handleFieldChange('mainEntityParseField', value)}
          >
            <SelectLabel>{t_i18n('Parse Field Type')}</SelectLabel>
            <SelectTrigger className="w-full">
              <SelectValue />
            </SelectTrigger>
            <SelectContent aria-label={t_i18n('Parse Field Type')}>
              <SelectItem value="text">{t_i18n('Text')}</SelectItem>
              <SelectItem value="textarea">{t_i18n('Text Area')}</SelectItem>
            </SelectContent>
          </Select>
          <Select
            value={formData.mainEntityParseMode}
            onValueChange={(value) => handleFieldChange('mainEntityParseMode', value)}
          >
            <SelectLabel>{t_i18n('Parse Mode')}</SelectLabel>
            <SelectTrigger className="w-full">
              <SelectValue />
            </SelectTrigger>
            <SelectContent aria-label={t_i18n('Parse Mode')}>
              <SelectItem value="comma">{t_i18n('Comma-separated')}</SelectItem>
              {formData.mainEntityParseField === 'textarea' && (
                <SelectItem value="line">{t_i18n('One per line')}</SelectItem>
              )}
            </SelectContent>
          </Select>
          <Select
            value={formData.mainEntityParseFieldMapping || ''}
            onValueChange={(value) => {
              const newMapping = value;
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
          >
            <SelectLabel>{t_i18n('Map parsed values to attribute')}</SelectLabel>
            <SelectTrigger className="w-full">
              <SelectValue />
            </SelectTrigger>
            <SelectContent aria-label={t_i18n('Map parsed values to attribute')}>
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
                  <SelectItem key={attr.value} value={attr.value}>
                    {attr.label}
                  </SelectItem>
                ));
              })()}
            </SelectContent>
          </Select>

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
            />
          )}
        </>
      )}

      {(() => {
        if (formData.mainEntityLookup) {
          return (
            <Alert
              severity="info"
              className={alertClassName}
              sx={{
                marginTop: 2.5,
                backgroundColor: 'transparent',
                border: '1px solid var(--color-filigran-brand-primary)',
              }}
            >
              {t_i18n('Entity lookup enabled. Users will select existing entities of this type.')}
            </Alert>
          );
        }
        if (formData.mainEntityFieldMode === 'parsed' && formData.mainEntityMultiple) {
          return (
            <>
              <Alert severity="info" className={alertClassName} style={{ marginTop: 20 }}>
                {t_i18n('Parsed mode enabled. Users can enter multiple values in a single field. Additional fields can be defined that will apply to all created entities.')}
              </Alert>
              {formData.mainEntityParseFieldMapping && (
                <div style={{ marginTop: 20 }}>
                  <Typography variant="h6" gutterBottom>
                    {t_i18n('Additional Fields (will be applied to all created entities)')}
                  </Typography>
                  {(() => {
                    const mainEntityParsedFields = (fieldsByEntity.main_entity || [])
                      .filter((field) => field.attributeMapping.attributeName !== formData.mainEntityParseFieldMapping);
                    return mainEntityParsedFields.map((field, idx) => renderField(field, idx, formData.mainEntityType, mainEntityParsedFields));
                  })()}
                  <Button
                    variant="secondary"
                    startIcon={<Add />}
                    onClick={() => handleAddField('main_entity', formData.mainEntityType)}
                    className={addButtonClassName}
                  >
                    {t_i18n('Add field')}
                  </Button>
                </div>
              )}
            </>
          );
        }
        const mainEntityFields = fieldsByEntity.main_entity || [];
        return (
          <Stack gap={2} sx={{ mt: 1 }}>
            <Typography variant="h6">
              {t_i18n('Main Entity Fields')}
            </Typography>
            {mainEntityFields.map((field, idx) => renderField(field, idx, formData.mainEntityType, mainEntityFields))}
            <div>
              <Button
                variant="secondary"
                startIcon={<Add />}
                onClick={() => handleAddField('main_entity', formData.mainEntityType)}
              >
                {t_i18n('Add field')}
              </Button>
            </div>
          </Stack>
        );
      })()}
    </Stack>
  );
};

export default MainEntitySection;
