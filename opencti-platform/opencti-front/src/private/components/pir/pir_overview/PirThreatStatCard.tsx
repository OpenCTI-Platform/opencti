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

import React from 'react';
import { Box, Stack, Typography } from '@mui/material';
import { alpha, useTheme } from '@mui/material/styles';
import type { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import { itemColor } from '../../../../utils/Colors';
import ItemIcon from '../../../../components/ItemIcon';
import NumberDifference from '../../../../components/NumberDifference';

interface PirThreatStatCardProps {
  label: string;
  entityType: string;
  value: number;
  diffValue: number;
  diffLabel: string;
}

const PirThreatStatCard = ({
  label,
  entityType,
  value,
  diffValue,
  diffLabel,
}: PirThreatStatCardProps) => {
  const theme = useTheme<Theme>();
  const { n } = useFormatter();
  const accent = itemColor(entityType);
  const subtleBorder = alpha(theme.palette.text.primary ?? '#ffffff', 0.05);

  return (
    <Box
      sx={{
        position: 'relative',
        height: '100%',
        overflow: 'hidden',
        borderRadius: 1,
        padding: 2,
        paddingLeft: 2.5,
        background: theme.palette.background.secondary,
        border: `1px solid ${subtleBorder}`,
        backgroundImage: `linear-gradient(135deg, ${alpha(accent, 0.16)} 0%, ${alpha(accent, 0)} 60%)`,
        transition: 'border-color 0.2s ease, transform 0.2s ease',
        '&:hover': {
          borderColor: alpha(accent, 0.45),
          transform: 'translateY(-2px)',
        },
      }}
    >
      <Box
        sx={{
          position: 'absolute',
          top: 0,
          left: 0,
          width: 3,
          height: '100%',
          background: accent,
        }}
      />
      <Stack
        direction="row"
        justifyContent="space-between"
        alignItems="flex-start"
        gap={1}
      >
        <Stack gap={0.75} sx={{ minWidth: 0 }}>
          <Typography
            sx={{
              color: theme.palette.text.light,
              fontSize: 12,
              fontWeight: 500,
              lineHeight: 1.2,
            }}
          >
            {label}
          </Typography>
          <Box
            data-testid={`card-number-${label}`}
            sx={{
              fontFamily: '"Geologica", sans-serif',
              fontSize: 30,
              fontWeight: 600,
              lineHeight: 1,
              color: theme.palette.text.primary,
            }}
          >
            {n(value)}
          </Box>
          <NumberDifference value={diffValue} description={diffLabel} />
        </Stack>
        <Box
          sx={{
            flexShrink: 0,
            width: 42,
            height: 42,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            borderRadius: 1,
            background: alpha(accent, 0.14),
            border: `1px solid ${alpha(accent, 0.35)}`,
          }}
        >
          <ItemIcon type={entityType} size="medium" color={accent} />
        </Box>
      </Stack>
    </Box>
  );
};

export default PirThreatStatCard;
