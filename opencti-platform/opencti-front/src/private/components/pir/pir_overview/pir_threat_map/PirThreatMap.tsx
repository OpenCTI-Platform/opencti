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

import React, { useState } from 'react';
import { alpha, useTheme } from '@mui/material/styles';
import { Box, Stack, Tooltip, Typography } from '@mui/material';
import { Link } from 'react-router-dom';
import { graphql, useFragment } from 'react-relay';
import { InfoOutlined } from '@mui/icons-material';
import type { Theme } from '../../../../../components/Theme';
import { useFormatter } from '../../../../../components/i18n';
import { PirThreatMapFragment$key } from './__generated__/PirThreatMapFragment.graphql';
import { getNodes } from '../../../../../utils/connection';
import { uniqueArray } from '../../../../../utils/utils';
import { pirEntityColor } from '../../pir-colors';
import ItemIcon from '../../../../../components/ItemIcon';
import { useComputeLink } from '../../../../../utils/hooks/useAppData';
import Card from '../../../../../components/common/card/Card';
import PirThreatMapLegend from './PirThreatMapLegend';

const pirThreatMapFragment = graphql`
  fragment PirThreatMapFragment on Query {
    stixDomainObjects(
      orderBy: refreshed_at
      orderMode: desc
      pirId: $pirId
      filters: $filters
    ) {
      edges {
        node {
          id
          refreshed_at
          entity_type
          representative {
            main
          }
          pirInformation(pirId: $pirId) {
            pir_score
          }
        }
      }
    }
  }
`;

const MAX_ITEMS = 12;

interface PirThreatMapProps {
  data: PirThreatMapFragment$key;
}

const PirThreatMap = ({ data }: PirThreatMapProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n, fsd } = useFormatter();
  const computeLink = useComputeLink();

  const { stixDomainObjects } = useFragment<PirThreatMapFragment$key>(pirThreatMapFragment, data);
  const nodes = getNodes(stixDomainObjects);

  const entityTypes = uniqueArray(nodes.flatMap((d) => (d?.entity_type ? [d.entity_type] : [])));
  const [filteredEntityTypes, setFilteredEntityTypes] = useState(entityTypes);

  const items = nodes
    .flatMap((d) => {
      const type = d?.entity_type ?? '';
      if (!filteredEntityTypes.includes(type)) return [];
      return [{
        id: d.id,
        type,
        name: d?.representative?.main ?? '',
        score: d?.pirInformation?.pir_score ?? 0,
        date: d?.refreshed_at,
      }];
    })
    .sort((a, b) => b.score - a.score || (new Date(b.date).getTime() - new Date(a.date).getTime()))
    .slice(0, MAX_ITEMS);

  const trackColor = alpha(theme.palette.text.primary ?? '#ffffff', 0.06);

  const title = (
    <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1) }}>
      {t_i18n('Most relevant threats')}
      <Tooltip title={t_i18n('Threats flagged in this PIR, ranked by their relevance score')}>
        <InfoOutlined
          color="primary"
          fontSize="small"
          style={{ paddingBottom: 2, paddingTop: 2 }}
        />
      </Tooltip>
    </div>
  );

  return (
    <Card title={title}>
      {items.length === 0 ? (
        <Typography variant="body2" color={theme.palette.text?.tertiary}>
          {t_i18n('No data has been found.')}
        </Typography>
      ) : (
        <Stack gap={0.5}>
          {items.map((item, index) => {
            const accent = pirEntityColor(item.type);
            const link = computeLink({ id: item.id, entity_type: item.type }) ?? '';
            const barWidth = `${Math.max(Math.min(item.score, 100), 2)}%`;

            return (
              <Box
                key={item.id}
                sx={{
                  borderRadius: 1,
                  transition: 'background 0.15s ease',
                  '&:hover': { background: theme.palette.background.accent },
                }}
              >
                <Link
                  to={link}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: theme.spacing(1.5),
                    padding: theme.spacing(1),
                    color: 'inherit',
                    textDecoration: 'none',
                  }}
                >
                  <Typography
                    sx={{
                      flexShrink: 0,
                      width: 18,
                      textAlign: 'right',
                      fontSize: 12,
                      color: theme.palette.text?.tertiary,
                    }}
                  >
                    {index + 1}
                  </Typography>
                  <Box
                    sx={{
                      flexShrink: 0,
                      width: 30,
                      height: 30,
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      borderRadius: 1,
                      background: alpha(accent, 0.14),
                      border: `1px solid ${alpha(accent, 0.35)}`,
                    }}
                  >
                    <ItemIcon type={item.type} color={accent} size="small" />
                  </Box>
                  <Box sx={{ flexShrink: 0, minWidth: 0, width: { xs: 110, sm: 180, md: 240 } }}>
                    <Typography noWrap sx={{ fontSize: 13, fontWeight: 600 }}>
                      {item.name}
                    </Typography>
                    <Typography noWrap sx={{ fontSize: 11, color: theme.palette.text?.tertiary }}>
                      {t_i18n(`entity_${item.type}`)}
                      {item.date ? ` · ${fsd(item.date)}` : ''}
                    </Typography>
                  </Box>
                  <Box
                    sx={{
                      flex: 1,
                      minWidth: 40,
                      height: 8,
                      borderRadius: 1,
                      background: trackColor,
                      overflow: 'hidden',
                    }}
                  >
                    <Box
                      sx={{
                        width: barWidth,
                        height: '100%',
                        borderRadius: 1,
                        background: `linear-gradient(90deg, ${alpha(accent, 0.45)}, ${accent})`,
                        boxShadow: `0 0 8px ${alpha(accent, 0.45)}`,
                      }}
                    />
                  </Box>
                  <Typography
                    sx={{
                      flexShrink: 0,
                      width: 34,
                      textAlign: 'right',
                      fontSize: 13,
                      fontWeight: 700,
                      color: accent,
                    }}
                  >
                    {item.score}
                  </Typography>
                </Link>
              </Box>
            );
          })}
        </Stack>
      )}
      {entityTypes.length > 1 && (
        <Box sx={{ marginTop: 2 }}>
          <PirThreatMapLegend
            entityTypes={entityTypes}
            onFilter={setFilteredEntityTypes}
          />
        </Box>
      )}
    </Card>
  );
};

export default PirThreatMap;
