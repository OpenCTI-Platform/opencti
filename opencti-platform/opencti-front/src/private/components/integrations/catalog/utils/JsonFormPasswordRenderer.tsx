import React from 'react';
import { and, ControlProps, isStringControl, RankedTester, rankWith, schemaMatches } from '@jsonforms/core';
import { withJsonFormsControlProps } from '@jsonforms/react';
import PasswordTextField from '../../../../../components/PasswordTextField';

export const JsonFormPasswordRenderer = ({ uischema, schema }: ControlProps) => {
  const scope = uischema?.scope || ''; // eg: uischema?.scope: '#/properties/SOME_KEY';
  const fieldName = scope.split('/').pop();

  let fieldLabel = '';
  if (fieldName && schema.properties) {
    fieldLabel = schema.properties[fieldName].description ?? '';
  }

  return <PasswordTextField name={fieldName} label={fieldLabel} />;
};

export const jsonFormPasswordTester: RankedTester = rankWith(
  10,
  and(
    isStringControl,
    schemaMatches((schema) => {
      return schema.type === 'string' && schema.format === 'password';
    }),
  ),
);
export default withJsonFormsControlProps(JsonFormPasswordRenderer);
