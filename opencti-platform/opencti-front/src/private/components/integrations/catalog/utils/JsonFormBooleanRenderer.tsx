import React from 'react';
import { ControlProps, isBooleanControl, RankedTester, rankWith } from '@jsonforms/core';
import { withJsonFormsControlProps } from '@jsonforms/react';
import { Checkbox } from '@filigran/design-system';

export const JsonFormBooleanRenderer = ({
  data,
  description,
  enabled,
  handleChange,
  id,
  label,
  path,
}: ControlProps) => (
  <Checkbox
    id={id}
    label={String(label)}
    description={description}
    checked={data === true}
    disabled={enabled === false}
    onCheckedChange={(checked) => handleChange(path, checked === true)}
  />
);

export const jsonFormBooleanTester: RankedTester = rankWith(6, isBooleanControl);

export default withJsonFormsControlProps(JsonFormBooleanRenderer);
