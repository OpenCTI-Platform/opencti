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

import React, { useMemo, useState } from 'react';
import { useTheme } from '@mui/material/styles';
import Grid from '@mui/material/Grid';
import { graphql, useFragment } from 'react-relay';
import { useNavigate } from 'react-router';
import { InfoOutlined } from '@mui/icons-material';
import Tooltip from '@mui/material/Tooltip';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@filigran/design-system';
import PirThreatMapTooltip from './PirThreatMapTooltip';
import useBuildScatterData from './useBuildScatterData';
import WidgetScatter from '../../../../../components/dashboard/WidgetScatter';
import type { Theme } from '../../../../../components/Theme';
import { useFormatter } from '../../../../../components/i18n';
import { PirThreatMapFragment$key } from './__generated__/PirThreatMapFragment.graphql';
import { getNodes } from '../../../../../utils/connection';
import PirThreatMapLegend from './PirThreatMapLegend';
import { uniqueArray } from '../../../../../utils/utils';
import { buildTypeStyles, PIR_THREAT_MAP_SCORE_BANDS, PIR_THREAT_MAP_WINDOWS, PirThreatMapMarker, PirThreatMapScoreBand, PirThreatMapWindow } from './pirThreatMapUtils';
import Card from '../../../../../components/common/card/Card';
import { colors } from '../../../../../utils/Charts';
import { useComputeLink } from '../../../../../utils/hooks/useAppData';

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
            pir_explanation {
              criterion {
                weight
              }
            }
          }
        }
      }
    }
  }
`;

interface PirThreatMapProps {
  data: PirThreatMapFragment$key;
  // Time window of the map, in days; the query is reloaded when it changes.
  days?: PirThreatMapWindow;
  onDaysChange?: (days: PirThreatMapWindow) => void;
}

const CHART_HEIGHT = 420;

const PirThreatMap = ({ data, days = 7, onDaysChange }: PirThreatMapProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const computeLink = useComputeLink();
  const [tooltipData, setTooltipData] = useState<PirThreatMapMarker[]>();
  const [tooltipPos, setTooltipPos] = useState({ x: 0, y: 0 });
  const [scoreMin, setScoreMin] = useState<PirThreatMapScoreBand>(0);

  const { stixDomainObjects } = useFragment<PirThreatMapFragment$key>(pirThreatMapFragment, data);
  const nodes = getNodes(stixDomainObjects);

  const entityTypes = uniqueArray(nodes.flatMap((d) => (d?.entity_type ? d.entity_type : []))).sort();
  const [filteredEntityTypes, setFilteredEntityTypes] = useState<string[] | null>(null);
  const shownTypes = filteredEntityTypes ?? entityTypes;

  const palette = useMemo(() => colors(theme.palette.mode === 'dark' ? 400 : 600), [theme.palette.mode]);
  const typeStyles = useMemo(() => buildTypeStyles(entityTypes, palette), [entityTypes.join(','), palette]);
  const counts = useMemo(() => {
    const result: Record<string, number> = {};
    nodes.forEach((d) => {
      if ((d.pirInformation?.pir_score ?? 0) >= scoreMin) {
        result[d.entity_type] = (result[d.entity_type] ?? 0) + 1;
      }
    });
    return result;
  }, [nodes, scoreMin]);

  // Clusters widen with the window so a 90-day map stays readable.
  const clusterMinutes = Math.round((days * 24 * 60) / 9);
  const { series, markerSizes, markerShapes } = useBuildScatterData({
    stixDomainObjects,
    entityTypes: shownTypes,
    typeStyles,
    scoreMin,
    clusterMinutes,
  });

  const title = (
    <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1) }}>
      {t_i18n('Threat map')}
      <Tooltip title={t_i18n('Threat map explanations...')}>
        <InfoOutlined
          color="primary"
          fontSize="small"
          style={{ paddingBottom: 2, paddingTop: 2 }}
        />
      </Tooltip>
    </div>
  );

  const action = (
    <div style={{ display: 'flex', gap: theme.spacing(1), alignItems: 'center' }}>
      {/* A ButtonGroupItem renders a glyph only (LIBRARY-FEEDBACK #63): text choices use the FDS Select. */}
      <Select
        value={String(scoreMin)}
        onValueChange={(value: string) => setScoreMin(Number(value) as PirThreatMapScoreBand)}
      >
        <SelectTrigger aria-label={t_i18n('Score band')}>
          <SelectValue />
        </SelectTrigger>
        <SelectContent aria-label={t_i18n('Score band')}>
          {PIR_THREAT_MAP_SCORE_BANDS.map((band) => (
            <SelectItem key={band} value={String(band)}>
              {band === 0 ? t_i18n('All scores') : `≥ ${band}`}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      {onDaysChange && (
        <Select
          value={String(days)}
          onValueChange={(value: string) => onDaysChange(Number(value) as PirThreatMapWindow)}
        >
          <SelectTrigger aria-label={t_i18n('Time window')}>
            <SelectValue />
          </SelectTrigger>
          <SelectContent aria-label={t_i18n('Time window')}>
            {PIR_THREAT_MAP_WINDOWS.map((window) => (
              <SelectItem key={window} value={String(window)}>
                {t_i18n('{count, plural, one {# day} other {# days}}', { values: { count: window } })}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      )}
    </div>
  );

  return (
    <Grid size={{ xs: 12 }}>
      <Card title={title} action={action}>
        <div style={{ position: 'relative', fontSize: 12 }}>
          <div style={{ height: CHART_HEIGHT }}>
            <WidgetScatter
              series={series}
              options={{
                background: theme.palette.background.accent,
                days,
                showAxes: true,
                yTitle: t_i18n('PIR score'),
                markerSizes,
                markerShapes,
                // Called when mouse hover a node on map.
                dataPointMouseEnter: (e, _, opts) => {
                  const apexSeries = opts.w.config.series[opts.seriesIndex];
                  const item = apexSeries.data[opts.dataPointIndex].meta.group as PirThreatMapMarker[];
                  setTooltipData(item);
                  setTooltipPos({ x: e.offsetX, y: e.offsetY });
                },
                // A click on a single entity opens it; a click on a cluster keeps its list open.
                dataPointSelection: (e, _, opts) => {
                  const apexSeries = opts.w.config.series[opts.seriesIndex];
                  const group = apexSeries.data[opts.dataPointIndex].meta.group as PirThreatMapMarker[];
                  if (group.length === 1) {
                    const link = computeLink({ id: group[0].id, entity_type: group[0].type });
                    if (link) navigate(link);
                  } else {
                    setTooltipData(group);
                    setTooltipPos({ x: e.offsetX, y: e.offsetY });
                  }
                },
                labelsFormatter: (_, opts) => {
                  const apexSeries = opts.w.config.series[opts.seriesIndex];
                  const item = apexSeries.data[opts.dataPointIndex].meta;
                  return item.size > 1 ? item.size : '';
                },
              }}
            />
          </div>
          {series.length === 0 && (
            <div style={{
              position: 'absolute',
              inset: 0,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: theme.palette.text?.secondary,
            }}
            >
              {t_i18n('No entity matches the selected filters in this time window')}
            </div>
          )}
        </div>
        <PirThreatMapLegend
          entityTypes={entityTypes}
          typeStyles={typeStyles}
          counts={counts}
          onFilter={setFilteredEntityTypes}
        />
        <PirThreatMapTooltip
          data={tooltipData}
          typeStyles={typeStyles}
          x={tooltipPos.x}
          y={tooltipPos.y}
          onMouseLeave={() => setTooltipData(undefined)}
        />
      </Card>
    </Grid>
  );
};

export default PirThreatMap;
