import React, { CSSProperties } from 'react';
import { useFormikContext } from 'formik';
import { Box, CardActionArea, Typography, CardContent, Card } from '@mui/material';
import { useFormatter } from '../../../components/i18n';
import { PirCreationFormData } from './pir-form-utils';

const PirCreationFormType = () => {
  const { t_i18n } = useFormatter();
  const { setFieldValue, values } = useFormikContext<PirCreationFormData>();

  const types = [
    {
      id: 'threat-landscape',
      label: t_i18n('Threat landscape'),
      description: t_i18n('Threat landscape description ...'),
    },
    {
      id: 'threat-origin',
      label: t_i18n('Threat origin (coming soon)'),
      description: t_i18n('Threat origin description ...'),
    },
    {
      id: 'threat-custom',
      label: t_i18n('Threat with full customization (coming soon)'),
      description: t_i18n('Threat with full customization description ...'),
    },
  ];

  return (
    <Box sx={{ display: 'flex', gap: 2 }}>
      {types.map(({ label, description, id }, i) => {
        const disabled = id !== 'threat-landscape';
        const cardStyle: CSSProperties = { flex: 1 };
        if (values.type === id) cardStyle.borderColor = 'primary.main';
        if (disabled) cardStyle.opacity = 0.7;

        return (
          <Card key={i} variant="outlined" sx={cardStyle}>
            <CardActionArea
              sx={{ height: '100%' }}
              disabled={disabled}
              onClick={() => setFieldValue('type', id)}
            >
              <CardContent sx={{ height: '100%' }}>
                <Typography variant="h4" sx={{ height: 'initial' }}>{label}</Typography>
                <Typography variant="body2">{description}</Typography>
              </CardContent>
            </CardActionArea>
          </Card>
        );
      })}
    </Box>
  );
};

export default PirCreationFormType;
