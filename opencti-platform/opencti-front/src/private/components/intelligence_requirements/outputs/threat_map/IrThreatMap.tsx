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
import { InfoOutlined } from '@mui/icons-material';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import IrThreatMapTooltip from './IrThreatMapTooltip';
import useBuildScatterData from './useBuildScatterData';
import WidgetScatter from '../../../../../components/dashboard/WidgetScatter';
import type { Theme } from '../../../../../components/Theme';
import { useFormatter } from '../../../../../components/i18n';
import IrThreatMapLegend from './IrThreatMapLegend';
import { uniqueArray } from '../../../../../utils/utils';
import {
  buildTypeStyles,
  IR_THREAT_MAP_SCORE_BANDS,
  IR_THREAT_MAP_WINDOWS,
  IrThreatMapMarker,
  IrThreatMapMatch,
  IrThreatMapScoreBand,
  IrThreatMapWindow,
  toThreatMapMarkers,
} from './irThreatMapUtils';
import Card from '../../../../../components/common/card/Card';
import { colors } from '../../../../../utils/Charts';

// Threat map of an intelligence requirement (plan step 4 of the PIR v2 replacement): the entities of the requirement
// placed by score (vertical) and last fact (horizontal), one colour and one shape per entity type.

interface IrThreatMapProps {
  matches: readonly IrThreatMapMatch[];
  // Opens the match drawer of the requirement (a click on one entity, or on a row of a cluster).
  onOpen: (matchId: string) => void;
}

const CHART_HEIGHT = 420;

const IrThreatMap = ({ matches, onOpen }: IrThreatMapProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const [days, setDays] = useState<IrThreatMapWindow>(30);
  const [tooltipData, setTooltipData] = useState<IrThreatMapMarker[]>();
  const [tooltipPos, setTooltipPos] = useState({ x: 0, y: 0 });
  const [scoreMin, setScoreMin] = useState<IrThreatMapScoreBand>(0);

  const markers = useMemo(() => toThreatMapMarkers(matches, days), [matches, days]);
  const entityTypes = uniqueArray(markers.map((m) => m.type)).sort();
  const [filteredEntityTypes, setFilteredEntityTypes] = useState<string[] | null>(null);
  const shownTypes = filteredEntityTypes ?? entityTypes;

  const palette = useMemo(() => colors(theme.palette.mode === 'dark' ? 400 : 600), [theme.palette.mode]);
  const typeStyles = useMemo(() => buildTypeStyles(entityTypes, palette), [entityTypes.join(','), palette]);
  const counts = useMemo(() => {
    const result: Record<string, number> = {};
    markers.forEach((m) => {
      if (m.score >= scoreMin) result[m.type] = (result[m.type] ?? 0) + 1;
    });
    return result;
  }, [markers, scoreMin]);

  // Clusters widen with the window so a 90-day map stays readable.
  const clusterMinutes = Math.round((days * 24 * 60) / 9);
  const { series, markerSizes, markerShapes } = useBuildScatterData({
    markers,
    entityTypes: shownTypes,
    typeStyles,
    scoreMin,
    clusterMinutes,
  });

  const open = (matchId: string) => {
    setTooltipData(undefined);
    onOpen(matchId);
  };

  const title = (
    <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1) }}>
      {t_i18n('Threat map')}
      <Tooltip>
        <TooltipTrigger asChild>
          <InfoOutlined
            color="primary"
            fontSize="small"
            aria-label={t_i18n('Threat map explanations...')}
            style={{ paddingBottom: 2, paddingTop: 2 }}
          />
        </TooltipTrigger>
        <TooltipContent>{t_i18n('Threat map explanations...')}</TooltipContent>
      </Tooltip>
    </div>
  );

  const action = (
    <div style={{ display: 'flex', gap: theme.spacing(1), alignItems: 'center' }}>
      {/* A ButtonGroupItem renders a glyph only (LIBRARY-FEEDBACK #63): text choices use the FDS Select. */}
      <Select
        value={String(scoreMin)}
        onValueChange={(value: string) => setScoreMin(Number(value) as IrThreatMapScoreBand)}
      >
        <SelectTrigger aria-label={t_i18n('Score band')}>
          <SelectValue />
        </SelectTrigger>
        <SelectContent aria-label={t_i18n('Score band')}>
          {IR_THREAT_MAP_SCORE_BANDS.map((band) => (
            <SelectItem key={band} value={String(band)}>
              {band === 0 ? t_i18n('All scores') : `≥ ${band}`}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      <Select
        value={String(days)}
        onValueChange={(value: string) => setDays(Number(value) as IrThreatMapWindow)}
      >
        <SelectTrigger aria-label={t_i18n('Time window')}>
          <SelectValue />
        </SelectTrigger>
        <SelectContent aria-label={t_i18n('Time window')}>
          {IR_THREAT_MAP_WINDOWS.map((window) => (
            <SelectItem key={window} value={String(window)}>
              {t_i18n('{count, plural, one {# day} other {# days}}', { values: { count: window } })}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  );

  return (
    <Card title={title} action={action}>
      <div style={{ position: 'relative', fontSize: 12 }}>
        <div style={{ height: CHART_HEIGHT }}>
          <WidgetScatter
            series={series}
            options={{
              background: theme.palette.background.accent,
              days,
              showAxes: true,
              yTitle: t_i18n('Score'),
              markerSizes,
              markerShapes,
              // Called when the mouse hovers a marker of the map.
              dataPointMouseEnter: (e, _, opts) => {
                const apexSeries = opts.w.config.series[opts.seriesIndex];
                setTooltipData(apexSeries.data[opts.dataPointIndex].meta.group as IrThreatMapMarker[]);
                setTooltipPos({ x: e.offsetX, y: e.offsetY });
              },
              // A click on a single entity opens its details; a click on a cluster keeps its list open.
              dataPointSelection: (e, _, opts) => {
                const apexSeries = opts.w.config.series[opts.seriesIndex];
                const group = apexSeries.data[opts.dataPointIndex].meta.group as IrThreatMapMarker[];
                if (group.length === 1) {
                  open(group[0].id);
                } else {
                  setTooltipData(group);
                  setTooltipPos({ x: e.offsetX, y: e.offsetY });
                }
              },
              labelsFormatter: (_, opts) => {
                const item = opts.w.config.series[opts.seriesIndex].data[opts.dataPointIndex].meta;
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
      <IrThreatMapLegend
        entityTypes={entityTypes}
        typeStyles={typeStyles}
        counts={counts}
        onFilter={setFilteredEntityTypes}
      />
      <IrThreatMapTooltip
        data={tooltipData}
        typeStyles={typeStyles}
        x={tooltipPos.x}
        y={tooltipPos.y}
        onOpen={open}
        onMouseLeave={() => setTooltipData(undefined)}
      />
    </Card>
  );
};

export default IrThreatMap;
