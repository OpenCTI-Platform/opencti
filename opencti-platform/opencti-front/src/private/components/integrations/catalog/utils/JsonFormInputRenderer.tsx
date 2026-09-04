import React from 'react';
import { ControlProps, isIntegerControl, isNumberControl, isStringControl, or, RankedTester, rankWith } from '@jsonforms/core';
import { withJsonFormsControlProps } from '@jsonforms/react';
import { Input } from '@filigran/design-system';

export const JsonFormInputRenderer = ({
  data,
  description,
  enabled,
  errors,
  handleChange,
  id,
  label,
  path,
  required,
  schema,
}: ControlProps) => {
  const isNumeric = schema.type === 'number' || schema.type === 'integer';

  return (
    <Input
      id={id}
      label={String(label)}
      required={required}
      disabled={enabled === false}
      type={isNumeric ? 'number' : 'text'}
      isTypeNumber={isNumeric}
      value={data ?? ''}
      error={errors || undefined}
      helperText={description}
      onChange={(event) => {
        const next = event.target.value;
        if (next === '') {
          handleChange(path, schema.default === null ? null : undefined);
          return;
        }
        handleChange(path, isNumeric ? Number(next) : next);
      }}
    />
  );
};

export const jsonFormInputTester: RankedTester = rankWith(
  5,
  or(isStringControl, isNumberControl, isIntegerControl),
);

export default withJsonFormsControlProps(JsonFormInputRenderer);
