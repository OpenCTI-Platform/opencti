import type React from 'react';
import { Field } from 'formik';
import DateTimePickerField from '../../../../../../components/DateTimePickerField';
import CreatedByField from '../../../../common/form/CreatedByField';
import ObjectMarkingField from '../../../../common/form/ObjectMarkingField';
import ObjectLabelField from '../../../../common/form/ObjectLabelField';
import { ExternalReferencesField } from '../../../../common/form/ExternalReferencesField';
import type { FieldOption } from '../../../../../../utils/field';
import { fieldSpacingContainerStyle } from '../../../../../../utils/field';
import { registerFieldRenderer } from './registry';
import type { FieldRendererContext } from './types';

const renderDateField = ({
  field,
  fieldPrefix,
}: FieldRendererContext): React.ReactNode => {
  const fieldName = fieldPrefix ? `${fieldPrefix}.${field.name}` : field.name;
  const displayLabel = field.label || field.attributeMapping.attributeName;

  return (
    <Field
      component={DateTimePickerField}
      name={fieldName}
      withSeconds={false}
      textFieldProps={{
        label: displayLabel,
        required: field.isMandatory,
        variant: 'outlined',
        fullWidth: true,
        style: fieldSpacingContainerStyle,
        helperText: field.description,
      }}
    />
  );
};

const renderDatetimeField = ({
  field,
  fieldPrefix,
}: FieldRendererContext): React.ReactNode => {
  const fieldName = fieldPrefix ? `${fieldPrefix}.${field.name}` : field.name;
  const displayLabel = field.label || field.attributeMapping.attributeName;

  return (
    <Field
      component={DateTimePickerField}
      name={fieldName}
      withSeconds={true}
      textFieldProps={{
        label: displayLabel,
        required: field.isMandatory,
        variant: 'outlined',
        fullWidth: true,
        style: fieldSpacingContainerStyle,
        helperText: field.description,
      }}
    />
  );
};

const renderCreatedByField = ({
  field,
  fieldPrefix,
  setFieldValue,
}: FieldRendererContext): React.ReactNode => {
  const fieldName = fieldPrefix ? `${fieldPrefix}.${field.name}` : field.name;
  const displayLabel = field.label || field.attributeMapping.attributeName;

  return (
    <CreatedByField
      name={fieldName}
      label={displayLabel}
      style={fieldSpacingContainerStyle}
      required={field.isMandatory}
      setFieldValue={setFieldValue}
    />
  );
};

const renderObjectMarkingField = ({
  field,
  fieldPrefix,
  setFieldValue,
}: FieldRendererContext): React.ReactNode => {
  const fieldName = fieldPrefix ? `${fieldPrefix}.${field.name}` : field.name;
  const displayLabel = field.label || field.attributeMapping.attributeName;

  return (
    <ObjectMarkingField
      name={fieldName}
      label={displayLabel}
      style={fieldSpacingContainerStyle}
      required={field.isMandatory}
      setFieldValue={setFieldValue}
    />
  );
};

const renderObjectLabelField = ({
  field,
  values,
  fieldPrefix,
  setFieldValue,
  getNestedValue,
}: FieldRendererContext): React.ReactNode => {
  const fieldName = fieldPrefix ? `${fieldPrefix}.${field.name}` : field.name;
  const fieldValue = fieldPrefix ? getNestedValue(values, fieldName) : (values[field.name] || '');

  return (
    <ObjectLabelField
      name={fieldName}
      style={fieldSpacingContainerStyle}
      required={field.isMandatory}
      setFieldValue={setFieldValue}
      values={fieldValue as FieldOption[]}
    />
  );
};

const renderExternalReferencesField = ({
  field,
  values,
  fieldPrefix,
  setFieldValue,
  getNestedValue,
}: FieldRendererContext): React.ReactNode => {
  const fieldName = fieldPrefix ? `${fieldPrefix}.${field.name}` : field.name;
  const fieldValue = fieldPrefix ? getNestedValue(values, fieldName) : (values[field.name] || '');

  return (
    <ExternalReferencesField
      name={fieldName}
      style={fieldSpacingContainerStyle}
      setFieldValue={setFieldValue}
      values={fieldValue as {
        label?: string;
        value: string;
        entity?: {
          created: string;
          description?: string | null;
          external_id?: string | null;
          id: string;
          source_name: string;
          url?: string | null;
        };
      }[]}
      required={field.isMandatory}
    />
  );
};

registerFieldRenderer('date', renderDateField);
registerFieldRenderer('datetime', renderDatetimeField);
registerFieldRenderer('createdBy', renderCreatedByField);
registerFieldRenderer('objectMarking', renderObjectMarkingField);
registerFieldRenderer('objectLabel', renderObjectLabelField);
registerFieldRenderer('externalReferences', renderExternalReferencesField);
