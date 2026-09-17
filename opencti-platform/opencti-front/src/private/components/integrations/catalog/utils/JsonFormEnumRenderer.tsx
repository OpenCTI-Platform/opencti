import React from 'react';
import { ControlProps, isEnumControl, RankedTester, rankWith } from '@jsonforms/core';
import { withJsonFormsEnumProps } from '@jsonforms/react';
import { Select, SelectContent, SelectHelperText, SelectItem, SelectLabel, SelectTrigger, SelectValue } from '@filigran/design-system';

type EnumOption = { label: string; value: string };

export const JsonFormEnumRenderer = ({
  data,
  description,
  enabled,
  errors,
  handleChange,
  label,
  options,
  path,
  required,
}: ControlProps & { options?: EnumOption[] }) => (
  <Select
    value={data ?? ''}
    onValueChange={(next) => handleChange(path, next)}
    disabled={enabled === false}
    required={required}
    error={!!errors}
  >
    <SelectLabel>{String(label)}</SelectLabel>
    <SelectTrigger className="w-full">
      <SelectValue />
    </SelectTrigger>
    <SelectContent aria-label={String(label)}>
      {(options ?? []).map((option) => (
        <SelectItem key={option.value} value={option.value}>
          {option.label}
        </SelectItem>
      ))}
    </SelectContent>
    {(errors || description) ? (
      <SelectHelperText>{errors || description}</SelectHelperText>
    ) : null}
  </Select>
);

export const jsonFormEnumTester: RankedTester = rankWith(6, isEnumControl);

export default withJsonFormsEnumProps(JsonFormEnumRenderer);
