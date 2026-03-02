import { FormFieldDefinition } from '@components/data/forms/Form';
import FormFieldRenderer, { FormFieldRendererProps } from '@components/data/forms/view/FormFieldRenderer';
import Grid from '@mui/material/Grid';
import React from 'react';

// Render a list of FormFieldRenderer, wrapping in a Grid layout when any field has a width defined.

const FormFields = ({
  fields,
  values,
  errors,
  touched,
  setFieldValue,
  entitySettings,
  fieldPrefix,
  getFieldKey,
  getFieldOverride,
}: {
  fields: FormFieldDefinition[];
  values: Record<string, unknown>;
  errors: Record<string, string>;
  touched: Record<string, boolean>;
  setFieldValue: FormFieldRendererProps['setFieldValue'];
  entitySettings: FormFieldRendererProps['entitySettings'];
  fieldPrefix?: string;
  getFieldKey: (field: FormFieldDefinition) => string;
  getFieldOverride?: (field: FormFieldDefinition) => Partial<FormFieldDefinition>;
}) => {
  const hasWidthDefined = fields.some((f) => f.width && f.width !== 'full');
  const renderers = fields.map((field) => {
    const override = getFieldOverride?.(field);
    const resolvedField = override ? { ...field, ...override } : field;
    return (
      <FormFieldRenderer
        key={getFieldKey(field)}
        field={resolvedField}
        values={values}
        errors={errors}
        touched={touched}
        setFieldValue={setFieldValue}
        entitySettings={entitySettings}
        fieldPrefix={fieldPrefix}
        useGridLayout={hasWidthDefined || undefined}
      />
    );
  });
  if (hasWidthDefined) {
    return <Grid container spacing={2}>{renderers}</Grid>;
  }
  return <>{renderers}</>;
};

export default FormFields;
