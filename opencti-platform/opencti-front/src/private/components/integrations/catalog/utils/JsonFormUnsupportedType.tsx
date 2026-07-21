import React from 'react';
import { Alert, Box, Typography } from '@mui/material';
import { ControlProps, isControl, and, schemaMatches, RankedTester, rankWith } from '@jsonforms/core';
import { withJsonFormsControlProps } from '@jsonforms/react';
import { useFormatter } from '../../../../../components/i18n';

const SUPPORTED_TYPES = [
  'string',
  'boolean',
  'integer',
  'number',
  'array',
];

export const isSupportedType = (schemaType: string | string[]): boolean => {
  if (!schemaType) return false;

  if (typeof schemaType === 'string') {
    return SUPPORTED_TYPES.includes(schemaType);
  }

  if (Array.isArray(schemaType)) {
    return schemaType.every((t) => SUPPORTED_TYPES.includes(t));
  }

  return false;
};

export const jsonFormUnsupportedTypeTester: RankedTester = rankWith(
  100,
  and(
    isControl,
    schemaMatches((schema) => {
      const matchesSupportedType = schema.type && isSupportedType(schema.type);
      return !matchesSupportedType;
    }),
  ),
);

const UnsupportedTypeRenderer: React.FC<ControlProps> = ({
  label,
}) => {
  const { t_i18n } = useFormatter();

  return (
    <Box sx={{ mb: 2, mt: 2 }}>
      <Alert
        severity="warning"
        variant="outlined"
        sx={{
          '& .MuiAlert-message': {
            width: '100%',
          },
        }}
      >
        <Typography>{label} {t_i18n('- Unsupported')}</Typography>
      </Alert>
    </Box>
  );
};

export default withJsonFormsControlProps(UnsupportedTypeRenderer);
