/*
Copyright (c) 2021-2025 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Enterprise Edition License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import React, { CSSProperties } from 'react';
import { useFormikContext } from 'formik';
import { Box, CardActionArea, Typography, CardContent, Card } from '@mui/material';
import { useFormatter } from '../../../../components/i18n';
import { PirCreationFormData } from './pir-form-utils';

const PirCreationFormType = () => {
  const { t_i18n } = useFormatter();
  const { setFieldValue, values } = useFormikContext<PirCreationFormData>();

  const types = [
    {
      id: 'THREAT_LANDSCAPE',
      label: t_i18n('Threat landscape'),
      description: t_i18n('Threat landscape description ...'),
    },
    {
      id: 'THREAT_ORIGIN',
      label: t_i18n('Threat origin (coming soon)'),
      description: t_i18n('Threat origin description ...'),
    },
    {
      id: 'THREAT_CUSTOM',
      label: t_i18n('Threat with full customization (coming soon)'),
      description: t_i18n('Threat with full customization description ...'),
    },
  ];

  return (
    <Box sx={{ display: 'flex', gap: 2 }}>
      {types.map(({ label, description, id }, i) => {
        const disabled = id !== 'THREAT_LANDSCAPE';
        const cardStyle: CSSProperties = { flex: 1 };
        if (values.pir_type === id) cardStyle.borderColor = 'primary.main';
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
