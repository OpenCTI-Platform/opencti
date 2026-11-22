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
import { Link } from 'react-router';
import { Box } from '@mui/material';
import type { Theme } from '../../../../../components/Theme';
import { PirThreatMapMarker, PirThreatMapTypeStyle } from './pirThreatMapUtils';
import { itemColor } from '../../../../../utils/Colors';
import { useFormatter } from '../../../../../components/i18n';
import { useComputeLink } from '../../../../../utils/hooks/useAppData';
import PirThreatMapShape from './PirThreatMapShape';

interface PirThreatMapTooltipProps {
  data?: PirThreatMapMarker[];
  typeStyles?: Record<string, PirThreatMapTypeStyle>;
  onMouseLeave?: MouseEventHandler;
  x: number;
  y: number;
}

export const PIR_THREAT_MAP_TOOLTIP_MAX_ITEMS = 8;

const PirThreatMapTooltip = ({
  data,
  typeStyles,
  onMouseLeave,
  x,
  y,
}: PirThreatMapTooltipProps) => {
  const { t_i18n, fsd } = useFormatter();
  const theme = useTheme<Theme>();
  const computeLink = useComputeLink();

  if (!data || data.length === 0) return null;

  const rows = data.slice(0, PIR_THREAT_MAP_TOOLTIP_MAX_ITEMS);
  const more = data.length - rows.length;

  const wrapperStyle: CSSProperties = {
    padding: theme.spacing(1.5),
    position: 'absolute',
    transform: 'translateX(calc(-100% + 40px))',
    top: y,
    left: x,
    zIndex: 2,
  };

  const containerStyle: CSSProperties = {
    background: theme.palette.background.nav,
    padding: theme.spacing(1),
    borderRadius: theme.borderRadius,
    border: `1px solid ${theme.palette.divider}`,
    fontSize: 12,
    display: 'flex',
    flexDirection: 'column',
    gap: theme.spacing(0.25),
    minWidth: 260,
    maxWidth: 360,
  };

  const rowStyle: CSSProperties = {
    display: 'grid',
    gridTemplateColumns: '12px 1fr auto',
    alignItems: 'center',
    columnGap: theme.spacing(1),
    color: theme.palette.text?.primary,
    textDecoration: 'none',
  };

  const secondary: CSSProperties = { color: theme.palette.text?.secondary, fontSize: 11 };

  return (
    <div style={wrapperStyle} onMouseLeave={onMouseLeave} role="dialog" aria-label={t_i18n('Threat map')}>
      <div style={containerStyle}>
        {data.length > 1 && (
          <div style={{ ...secondary, paddingBottom: theme.spacing(0.5) }}>
            {t_i18n('{count, plural, one {# entity} other {# entities}}', { values: { count: data.length } })}
          </div>
        )}
        {rows.map(({ type, id, name, date, score, matchedCriteria }) => {
          const link = computeLink({ id, entity_type: type }) ?? '';
          const style = typeStyles?.[type];
          return (
            <Box
              key={id}
              sx={{
                borderRadius: 1,
                padding: 0.5,
                '&:hover': {
                  background: theme.palette.background.shadow,
                },
              }}
            >
              <Link to={link} style={rowStyle}>
                <PirThreatMapShape shape={style?.shape ?? 'circle'} color={style?.color ?? itemColor(type)} />
                <span style={{ overflow: 'hidden' }}>
                  <span style={{ display: 'block', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', fontWeight: 600 }}>
                    {name}
                  </span>
                  <span style={{ ...secondary, display: 'block', whiteSpace: 'nowrap' }}>
                    {t_i18n(`entity_${type}`)} · {fsd(date)} · {t_i18n('{count, plural, one {# criterion matched} other {# criteria matched}}', { values: { count: matchedCriteria } })}
                  </span>
                </span>
                <span style={{ fontWeight: 700, fontSize: 14 }} aria-label={t_i18n('PIR score')}>{score}</span>
              </Link>
            </Box>
          );
        })}
        {more > 0 && (
          <div style={{ ...secondary, paddingTop: theme.spacing(0.5) }}>
            {t_i18n('{count, plural, one {# more entity} other {# more entities}}', { values: { count: more } })}
          </div>
        )}
      </div>
    </div>
  );
};

export default PirThreatMapTooltip;
