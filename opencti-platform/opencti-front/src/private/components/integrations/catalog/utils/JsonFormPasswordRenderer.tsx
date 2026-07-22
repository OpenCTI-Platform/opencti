import React from 'react';
import { and, ControlProps, isStringControl, RankedTester, rankWith, schemaMatches } from '@jsonforms/core';
import { withJsonFormsControlProps } from '@jsonforms/react';
import Box from '@mui/material/Box';
import PasswordTextField from '../../../../../components/PasswordTextField';

export const JsonFormPasswordRenderer = ({ uischema, schema }: ControlProps) => {
  const scope = uischema?.scope || ''; // eg: uischema?.scope: '#/properties/SOME_KEY';
  const fieldName = scope.split('/').pop();

  let fieldLabel = '';
  if (fieldName && schema.properties) {
    fieldLabel = schema.properties[fieldName].description ?? '';
  }

  return (
    <Box
      sx={{
        // override the PasswordTextField position icon button
        '& button[aria-label*="Show"], & button[aria-label*="Hide"]': {
          top: '50% !important',
          transform: 'translateY(-50%)',
        },
        // override the PasswordTextField container style
        '& > div > div': {
          margin: '0 !important',
        },
      }}
    >
      <PasswordTextField name={fieldName} label={fieldLabel} />
    </Box>
  );
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
