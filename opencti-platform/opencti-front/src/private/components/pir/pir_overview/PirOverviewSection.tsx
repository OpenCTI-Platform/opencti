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
import { useTheme } from '@mui/material/styles';
import type { Theme } from '../../../../components/Theme';

interface PirOverviewSectionProps {
  label: string;
  caption?: string;
  action?: ReactNode;
  fillHeight?: boolean;
  children: ReactNode;
}

const PirOverviewSection = ({
  label,
  caption,
  action,
  fillHeight = false,
  children,
}: PirOverviewSectionProps) => {
  const theme = useTheme<Theme>();

  return (
    <Box
      component="section"
      sx={{
        display: 'flex',
        flexDirection: 'column',
        gap: 1.5,
        ...(fillHeight ? { height: '100%' } : {}),
      }}
    >
      <Stack
        direction="row"
        alignItems="center"
        justifyContent="space-between"
        gap={1}
      >
        <Box sx={{ minWidth: 0 }}>
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
      <Box sx={fillHeight ? { flex: 1, minHeight: 0 } : undefined}>
        {children}
      </Box>
    </Box>
  );
};

export default PirOverviewSection;
