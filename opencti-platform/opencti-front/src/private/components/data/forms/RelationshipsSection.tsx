import Button from '@common/button/Button';
import { Add, DeleteOutlined } from '@mui/icons-material';
// fds:keep-mui Switch/TextField predate this PR; relationship fields still use MUI here.
import { Box, FormControlLabel, Stack, Switch, TextField, Typography } from '@mui/material';
import { IconButton, Select, SelectContent, SelectItem, SelectLabel, SelectTrigger, SelectValue } from '@filigran/design-system';
import React from 'react';
import { useFormatter } from '../../../../components/i18n';
import useAuth from '../../../../utils/hooks/useAuth';
import { resolveRelationsTypes } from '../../../../utils/Relation';
import type { EntityRelationship, FormBuilderData, FormFieldAttribute, RelationshipTypeOption } from './Form.d';
import { generateFieldId } from './FormUtils';
import useStyles from './useFormSchemaEditorStyles';

export interface RelationshipsSectionProps {
  formData: FormBuilderData;
  handleFieldChange: (path: string, value: unknown) => void;
  updateFormData: (updater: (prev: FormBuilderData) => FormBuilderData) => void;
  updateRelationshipEntity?: (
    relationshipId: string,
    side: 'fromEntity' | 'toEntity',
    entityId: string,
  ) => void;
  updateRelationshipType?: (relationshipId: string, relationshipType: string) => void;
  toggleRelationshipRequired?: (relationshipId: string, required: boolean) => void;
  handleRemoveRelationship: (relationshipId: string) => void;
  handleAddRelationship: () => void;
}

const RelationshipsSection: React.FC<RelationshipsSectionProps> = ({
  formData,
  handleFieldChange,
  updateFormData,
  updateRelationshipEntity,
  updateRelationshipType,
  toggleRelationshipRequired,
  handleRemoveRelationship,
  handleAddRelationship,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const { schema } = useAuth();
  const updateEntity = updateRelationshipEntity || ((relationshipId, side, entityId) => {
    const relationshipIndex = formData.relationships.findIndex((relationship) => relationship.id === relationshipId);
    handleFieldChange(`relationships.${relationshipIndex}.${side}`, entityId);
    if (formData.relationships[relationshipIndex]?.relationshipType) {
      handleFieldChange(`relationships.${relationshipIndex}.relationshipType`, '');
    }
  });
  const updateType = updateRelationshipType || ((relationshipId, relationshipType) => {
    const relationshipIndex = formData.relationships.findIndex((relationship) => relationship.id === relationshipId);
    handleFieldChange(`relationships.${relationshipIndex}.relationshipType`, relationshipType);
  });
  const updateRequired = toggleRelationshipRequired || ((relationshipId, required) => {
    const relationshipIndex = formData.relationships.findIndex((relationship) => relationship.id === relationshipId);
    handleFieldChange(`relationships.${relationshipIndex}.required`, required);
  });

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
            variant="destructive"
            priority="tertiary"
            aria-label={t_i18n('Delete')}
            size="sm"
            onClick={() => {
              const updatedRelationships = [...formData.relationships];
              updatedRelationships[relationshipIndex].fields = updatedRelationships[relationshipIndex].fields?.filter((_field, i) => i !== index);
              updateFormData((prev) => ({ ...prev, relationships: updatedRelationships }));
            }}
            icon={<DeleteOutlined />}
          />
        </div>

        <TextField
          fullWidth
          variant="outlined"
          label={t_i18n('Label')}
          value={field.label}
          onChange={(e) => {
            const label = e.target.value;
            // Auto-generate name from label
            const name = label.toLowerCase().replace(/\s+/g, '_').replace(/[^a-z0-9_]/g, '');
            handleFieldChange(`${fieldPath}.label`, label);
            handleFieldChange(`${fieldPath}.name`, name || field.id);
          }}
          className="mt-5"
        />

        <Select
          value={field.type}
          onValueChange={(value) => {
            handleFieldChange(`${fieldPath}.type`, value);
            // Reset attribute mapping when field type changes
            handleFieldChange(`${fieldPath}.attributeMapping.attributeName`, '');
          }}
        >
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
        </Select>

        <Select
          value={field.attributeMapping.attributeName}
          onValueChange={(value) => handleFieldChange(`${fieldPath}.attributeMapping.attributeName`, value)}
        >
          <SelectLabel>{t_i18n('Map to attribute')}</SelectLabel>
          <SelectTrigger className="w-full">
            <SelectValue placeholder={t_i18n('Select an attribute')} />
          </SelectTrigger>
          <SelectContent aria-label={t_i18n('Map to attribute')}>
            {availableAttributes.map((attr) => (
              <SelectItem key={attr.value} value={attr.value}>
                {attr.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

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
      <Stack key={relationship.id} className={classes.relationshipGroup} gap={2}>
        <div className={classes.fieldHeader}>
          <Typography className={classes.fieldTitle}>
            {t_i18n('Relationship')} {index + 1}
          </Typography>
          <IconButton
            variant="destructive"
            priority="tertiary"
            aria-label={t_i18n('Remove')}
            size="sm"
            onClick={() => handleRemoveRelationship(relationship.id)}
            icon={<DeleteOutlined />}
          />
        </div>

        <Select
          value={relationship.fromEntity}
          onValueChange={(value) => {
            updateEntity(relationship.id, 'fromEntity', value);
          }}
        >
          <div>
            <SelectLabel>{t_i18n('Source Entity')}</SelectLabel>
            <SelectTrigger className="w-full">
              <SelectValue />
            </SelectTrigger>
            <SelectContent aria-label={t_i18n('Source Entity')}>
              {entityOptions.map((opt) => (
                <SelectItem key={opt.value} value={opt.value}>
                  {opt.label}
                </SelectItem>
              ))}
            </SelectContent>
          </div>
        </Select>

        <Select
          value={relationship.toEntity}
          onValueChange={(value) => {
            updateEntity(relationship.id, 'toEntity', value);
          }}
        >
          <div>
            <SelectLabel>{t_i18n('Target Entity')}</SelectLabel>
            <SelectTrigger className="w-full">
              <SelectValue />
            </SelectTrigger>
            <SelectContent aria-label={t_i18n('Target Entity')}>
              {entityOptions.map((opt) => (
                <SelectItem key={opt.value} value={opt.value}>
                  {opt.label}
                </SelectItem>
              ))}
            </SelectContent>
          </div>
        </Select>

        <Select
          value={relationship.relationshipType}
          onValueChange={(value) => updateType(relationship.id, value)}
          disabled={!relationship.fromEntity || !relationship.toEntity}
        >
          <div>
            <SelectLabel>{t_i18n('Relationship Type')}</SelectLabel>
            <SelectTrigger className="w-full">
              <SelectValue />
            </SelectTrigger>
            <SelectContent aria-label={t_i18n('Relationship Type')}>
              {availableRelationships.map((rel) => (
                <SelectItem key={rel.value} value={rel.value}>
                  {rel.label}
                </SelectItem>
              ))}
            </SelectContent>
          </div>
        </Select>

        <FormControlLabel
          control={(
            <Switch
              checked={relationship.required || false}
              onChange={(e) => updateRequired(relationship.id, e.target.checked)}
            />
          )}
          label={t_i18n('Required')}
        />

        {/* Additional fields for relationship */}
        {relationship.relationshipType && (
          <div>
            <Typography variant="subtitle1">
              {t_i18n('Additional Fields')}
            </Typography>
            {(relationship.fields || []).map((field, fieldIdx) => renderRelationshipField(
              field,
              fieldIdx,
              relationshipIndex,
            ))}
            <div>
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
            </div>
          </div>

        )}
      </Stack>
    );
  };

  return (
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
  );
};

export default RelationshipsSection;
