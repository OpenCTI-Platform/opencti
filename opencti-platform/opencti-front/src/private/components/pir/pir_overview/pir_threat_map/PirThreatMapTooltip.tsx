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

import React, { CSSProperties, MouseEventHandler } from 'react';
import { useTheme } from '@mui/material/styles';
import { Link } from 'react-router-dom';
import { Box } from '@mui/material';
import type { Theme } from '../../../../../components/Theme';
import { PirThreatMapMarker } from './pirThreatMapUtils';
import { dateFormat } from '../../../../../utils/Time';
import { itemColor } from '../../../../../utils/Colors';
import { computeLink } from '../../../../../utils/Entity';

interface PirThreatMapTooltipProps {
  data?: PirThreatMapMarker[]
  onMouseLeave?: MouseEventHandler
  x: number
  y: number
}

const PirThreatMapTooltip = ({
  data,
  onMouseLeave,
  x,
  y,
}: PirThreatMapTooltipProps) => {
  const theme = useTheme<Theme>();

  if (!data) return null;

  const MAX_ITEMS = 10;
  const hasMore = data.length > MAX_ITEMS;
  const rows = data.slice(0, MAX_ITEMS);

  const wrapperStyle: CSSProperties = {
    padding: theme.spacing(2),
    position: 'absolute',
    transform: 'translateX(calc(-100% + 50px))',
    top: y,
    left: x,
  };

  const containerStyle: CSSProperties = {
    background: theme.palette.background.nav,
    padding: theme.spacing(0.5),
    borderRadius: theme.borderRadius,
    fontSize: '12px',
    display: 'flex',
    flexDirection: 'column',
  };

  const rowStyle: CSSProperties = {
    display: 'flex',
    alignItems: 'center',
    gap: theme.spacing(1),
    color: theme.palette.text?.primary,
  };

  return (
    <div style={wrapperStyle} onMouseLeave={onMouseLeave}>
      <div style={containerStyle}>
        {rows.map(({ type, id, name, date, score }) => {
          const link = computeLink({ id, entity_type: type }) ?? '';
          return (
            <Box
              key={name}
              sx={{
                borderRadius: 1,
                padding: 0.5,
                '&:hover': {
                  background: theme.palette.background.shadow,
                },
              }}
            >
              <Link to={link} style={rowStyle}>
                <div
                  style={{
                    width: '10px',
                    height: '10px',
                    borderRadius: '10px',
                    background: itemColor(type),
                  }}
                />
                <span style={{ whiteSpace: 'nowrap' }}>
                  {dateFormat(date)} - {name} ({score}%)
                </span>
              </Link>
            </Box>
          );
        })}
        {hasMore && <div>...</div>}
      </div>
    </div>
  );
};

export default PirThreatMapTooltip;
