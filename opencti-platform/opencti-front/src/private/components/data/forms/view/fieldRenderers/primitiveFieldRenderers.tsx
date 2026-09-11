import type React from 'react';
import { Field, FieldInputProps, FormikProps } from 'formik';
import FormControlLabel from '@mui/material/FormControlLabel';
import Checkbox from '@mui/material/Checkbox';
import TextField from '../../../../../../components/TextField';
import MarkdownField from '../../../../../../components/fields/markdownField/MarkdownField';
import SwitchField from '../../../../../../components/fields/SwitchField';
import { fieldSpacingContainerStyle } from '../../../../../../utils/field';
import { registerFieldRenderer } from './registry';
import type { FieldRendererContext } from './types';

const renderTextField = ({ field, fieldPrefix }: FieldRendererContext): React.ReactNode => {
  const fieldName = fieldPrefix ? `${fieldPrefix}.${field.name}` : field.name;
  const displayLabel = field.label || field.attributeMapping.attributeName;

  return (
    <Field
      component={TextField}
      name={fieldName}
      label={displayLabel}
      fullWidth={true}
      required={field.isMandatory}
      helperText={field.description}
      style={fieldSpacingContainerStyle}
    />
  );
};

const renderTextareaField = ({ field, fieldPrefix }: FieldRendererContext): React.ReactNode => {
  const fieldName = fieldPrefix ? `${fieldPrefix}.${field.name}` : field.name;
  const displayLabel = field.label || field.attributeMapping.attributeName;

  return (
    <Field
      component={MarkdownField}
      name={fieldName}
      label={displayLabel}
      fullWidth={true}
      required={field.isMandatory}
      style={fieldSpacingContainerStyle}
    />
  );
};

const renderNumberField = ({ field, fieldPrefix }: FieldRendererContext): React.ReactNode => {
  const fieldName = fieldPrefix ? `${fieldPrefix}.${field.name}` : field.name;
  const displayLabel = field.label || field.attributeMapping.attributeName;

  return (
    <Field
      component={TextField}
      name={fieldName}
      label={displayLabel}
      type="number"
      fullWidth={true}
      required={field.isMandatory}
      helperText={field.description}
      style={fieldSpacingContainerStyle}
    />
  );
};

const renderCheckboxField = ({ field, fieldPrefix }: FieldRendererContext): React.ReactNode => {
  const fieldName = fieldPrefix ? `${fieldPrefix}.${field.name}` : field.name;
  const displayLabel = field.label || field.attributeMapping.attributeName;

  return (
    <Field name={fieldName}>
      {({ field: formikField, form }: { field: FieldInputProps<boolean | string>; form: FormikProps<Record<string, unknown>> }) => (
        <FormControlLabel
          control={(
            <Checkbox
              {...formikField}
              checked={formikField.value === true || formikField.value === 'true' || formikField.value === '1'}
              onChange={(e) => {
                form.setFieldValue(fieldName, e.target.checked);
              }}
            />
          )}
          label={displayLabel}
          style={fieldSpacingContainerStyle}
        />
      )}
    </Field>
  );
};

const renderToggleField = ({ field, fieldPrefix }: FieldRendererContext): React.ReactNode => {
  const fieldName = fieldPrefix ? `${fieldPrefix}.${field.name}` : field.name;
  const displayLabel = field.label || field.attributeMapping.attributeName;

  return (
    <Field name={fieldName}>
      {({ field: formikField, form }: { field: FieldInputProps<boolean | string>; form: FormikProps<Record<string, unknown>> }) => (
        <SwitchField
          label={displayLabel}
          checked={formikField.value === true || formikField.value === 'true' || formikField.value === '1'}
          onChange={(value: boolean) => {
            form.setFieldValue(fieldName, value);
          }}
          containerstyle={fieldSpacingContainerStyle}
          helpertext={field.description}
        />
      )}
    </Field>
  );
};

const renderDefaultField = ({ field, fieldPrefix }: FieldRendererContext): React.ReactNode => {
  const fieldName = fieldPrefix ? `${fieldPrefix}.${field.name}` : field.name;
  const displayLabel = field.label || field.attributeMapping.attributeName;

  return (
    <Field
      component={TextField}
      name={fieldName}
      label={displayLabel}
      fullWidth={true}
      required={field.isMandatory}
      helperText={field.description}
      style={fieldSpacingContainerStyle}
    />
  );
};

registerFieldRenderer('text', renderTextField);
registerFieldRenderer('textarea', renderTextareaField);
registerFieldRenderer('number', renderNumberField);
registerFieldRenderer('checkbox', renderCheckboxField);
registerFieldRenderer('toggle', renderToggleField);
registerFieldRenderer('default', renderDefaultField);
