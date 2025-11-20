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

import React, { CSSProperties, useState } from 'react';
import { useTheme } from '@mui/material/styles';
import Grid from '@mui/material/Grid2';
import { graphql, useFragment } from 'react-relay';
import { InfoOutlined } from '@mui/icons-material';
import Tooltip from '@mui/material/Tooltip';
import PirThreatMapTooltip from './PirThreatMapTooltip';
import useBuildScatterData from './useBuildScatterData';
import WidgetScatter from '../../../../../components/dashboard/WidgetScatter';
import type { Theme } from '../../../../../components/Theme';
import Paper from '../../../../../components/Paper';
import { useFormatter } from '../../../../../components/i18n';
import { PirThreatMapFragment$key } from './__generated__/PirThreatMapFragment.graphql';
import { getNodes } from '../../../../../utils/connection';
import PirThreatMapLegend from './PirThreatMapLegend';
import { uniqueArray } from '../../../../../utils/utils';
import { PirThreatMapMarker } from './pirThreatMapUtils';

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

interface PirThreatMapProps {
  data: PirThreatMapFragment$key
}

const PirThreatMap = ({ data }: PirThreatMapProps) => {
  const CHART_SIZE = 500;
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const [tooltipData, setTooltipData] = useState<PirThreatMapMarker[]>();
  const [tooltipPos, setTooltipPos] = useState({ x: 0, y: 0 });

  const { stixDomainObjects } = useFragment<PirThreatMapFragment$key>(pirThreatMapFragment, data);

  const entityTypes = uniqueArray(getNodes(stixDomainObjects).flatMap((d) => {
    return d?.entity_type ? d.entity_type : [];
  }));
  const [filteredEntityTypes, setFilteredEntityTypes] = useState(entityTypes);

  const series = useBuildScatterData({
    stixDomainObjects,
    entityTypes: filteredEntityTypes,
  });

  const containerStyle: CSSProperties = {
    position: 'relative',
    paddingLeft: theme.spacing(1),
    paddingBottom: theme.spacing(1.5),
    fontSize: 12,
  };

  const axisStyle: CSSProperties = {
    position: 'absolute',
    display: 'flex',
    justifyContent: 'space-between',
  };

  const xStyle: CSSProperties = {
    ...axisStyle,
    bottom: -6,
    left: theme.spacing(1),
    right: 0,
  };

  const yStyle: CSSProperties = {
    ...axisStyle,
    transform: 'rotate(-90deg)',
    transformOrigin: 'top left',
    width: CHART_SIZE,
    left: -12,
  };

  const title = (
    <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1) }}>
      {t_i18n('Threat map')}
      <Tooltip title={t_i18n('Threat map explanations...')}>
        <InfoOutlined
          color='primary'
          fontSize="small"
          style={{ paddingBottom: 4, paddingTop: 1 }}
        />
      </Tooltip>
    </div>
  );

  return (
    <Grid size={{ xs: 12 }}>
      <Paper title={title}>
        <div style={containerStyle}>
          <div style={{ height: CHART_SIZE }}>
            <WidgetScatter
              series={series}
              options={{
                background: theme.palette.background.accent,
                // Called when mouse hover a node on map.
                dataPointMouseEnter: (e, _, opts) => {
                  const apexSeries = opts.w.config.series[opts.seriesIndex];
                  const item = apexSeries.data[opts.dataPointIndex].meta.group as PirThreatMapMarker[];
                  setTooltipData(item);
                  setTooltipPos({ x: e.offsetX, y: e.offsetY });
                },
                labelsFormatter: (_, opts) => {
                  const apexSeries = opts.w.config.series[opts.seriesIndex];
                  const item = apexSeries.data[opts.dataPointIndex].meta;
                  return item.size > 1 ? item.size : '';
                },
              }}
            />
          </div>
          <div style={xStyle}>
            <span>{t_i18n('One week ago')}</span>
            <span>{t_i18n('Today')}</span>
          </div>
          <div style={yStyle}>
            <span>{t_i18n('0 - Less relevant')}</span>
            <span>{t_i18n('Most relevant - 100')}</span>
          </div>
        </div>
        <PirThreatMapLegend
          entityTypes={entityTypes}
          onFilter={setFilteredEntityTypes}
        />
        <PirThreatMapTooltip
          data={tooltipData}
          x={tooltipPos.x}
          y={tooltipPos.y}
          onMouseLeave={() => setTooltipData(undefined)}
        />
      </Paper>
    </Grid>
  );
};

export default PirThreatMap;
