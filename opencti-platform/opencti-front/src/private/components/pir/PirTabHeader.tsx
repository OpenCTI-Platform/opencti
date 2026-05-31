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

import React, { ReactNode } from 'react';
import { Box, Stack, Typography } from '@mui/material';
import { alpha, useTheme } from '@mui/material/styles';
import type { Theme } from '../../../components/Theme';

interface PirTabHeaderProps {
  icon: ReactNode;
  label: string;
  caption?: string;
  action?: ReactNode;
}

const PirTabHeader = ({ icon, label, caption, action }: PirTabHeaderProps) => {
  const theme = useTheme<Theme>();
  const accent = theme.palette.primary.main ?? '#0fbcff';

  return (
    <Stack
      direction="row"
      alignItems="center"
      gap={1.5}
      sx={{ marginBottom: 2 }}
    >
      <Box
        sx={{
          flexShrink: 0,
          width: 40,
          height: 40,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          borderRadius: 1,
          color: accent,
          background: alpha(accent, 0.14),
          border: `1px solid ${alpha(accent, 0.35)}`,
        }}
      >
        {icon}
      </Box>
      <Box sx={{ flex: 1, minWidth: 0 }}>
        <Typography
          component="h2"
          sx={{
            margin: 0,
            fontFamily: '"Geologica", sans-serif',
            fontSize: 11,
            fontWeight: 600,
            letterSpacing: '0.12em',
            textTransform: 'uppercase',
            lineHeight: 1.3,
            color: theme.palette.text.primary,
          }}
        >
          {label}
        </Typography>
        {caption && (
          <Typography
            sx={{
              marginTop: 0.25,
              fontSize: 12,
              lineHeight: 1.3,
              color: theme.palette.text.tertiary,
            }}
          >
            {caption}
          </Typography>
        )}
      </Box>
      {action && (
        <Stack direction="row" alignItems="center" gap={1}>
          {action}
        </Stack>
      )}
    </Stack>
  );
};

export default PirTabHeader;
