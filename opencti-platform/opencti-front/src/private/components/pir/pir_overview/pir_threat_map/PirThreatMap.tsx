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
import { ApexOptions } from 'apexcharts';
import { alpha, useTheme } from '@mui/material/styles';
import Chart from '@components/common/charts/Chart';
import { graphql, useFragment } from 'react-relay';
import { InfoOutlined } from '@mui/icons-material';
import Tooltip from '@mui/material/Tooltip';
import PirThreatMapTooltip from './PirThreatMapTooltip';
import useBuildScatterData from './useBuildScatterData';
import type { Theme } from '../../../../../components/Theme';
import { useFormatter } from '../../../../../components/i18n';
import { PirThreatMapFragment$key } from './__generated__/PirThreatMapFragment.graphql';
import { getNodes } from '../../../../../utils/connection';
import { daysAgo, now } from '../../../../../utils/Time';
import PirThreatMapLegend from './PirThreatMapLegend';
import { uniqueArray } from '../../../../../utils/utils';
import { PirThreatMapMarker } from './pirThreatMapUtils';
import Card from '../../../../../components/common/card/Card';

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
  data: PirThreatMapFragment$key;
}

const CHART_HEIGHT = 360;

const PirThreatMap = ({ data }: PirThreatMapProps) => {
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

  // Bigger bubbles for clusters that group several entities together.
  const markerSizes = series.map((s) => {
    const size = s.data[0]?.meta.size ?? 1;
    return Math.min(8 + (size - 1) * 2.5, 22);
  });

  const gridColor = alpha(theme.palette.text.primary ?? '#ffffff', 0.06);
  const bandColor = alpha(theme.palette.warn?.main ?? '#E6700F', 0.07);
  const strokeColor = theme.palette.background.paper ?? '#09101e';

  const options: ApexOptions = {
    chart: {
      type: 'scatter',
      background: 'transparent',
      toolbar: { show: false },
      zoom: { enabled: false },
      foreColor: theme.palette.text?.tertiary,
      fontFamily: '"IBM Plex Sans", sans-serif',
      events: {
        // Called when mouse hover a node on map.
        dataPointMouseEnter: (e, _, opts) => {
          const apexSeries = opts.w.config.series[opts.seriesIndex];
          const item = apexSeries.data[opts.dataPointIndex].meta.group as PirThreatMapMarker[];
          setTooltipData(item);
          setTooltipPos({ x: e.offsetX, y: e.offsetY });
        },
      },
    },
    theme: { mode: theme.palette.mode },
    dataLabels: {
      enabled: true,
      offsetY: 1,
      background: { enabled: false },
      style: { colors: ['#000000'], fontSize: '10px', fontWeight: '700' },
      formatter: (_, opts) => {
        const apexSeries = opts.w.config.series[opts.seriesIndex];
        const item = apexSeries.data[opts.dataPointIndex].meta;
        return item.size > 1 ? String(item.size) : '';
      },
    },
    grid: {
      show: true,
      borderColor: gridColor,
      strokeDashArray: 4,
      xaxis: { lines: { show: true } },
      yaxis: { lines: { show: true } },
      padding: { top: 4, right: 8, bottom: 4, left: 8 },
    },
    legend: { show: false },
    tooltip: { enabled: false },
    xaxis: {
      type: 'datetime',
      min: new Date(daysAgo(7)).getTime(),
      max: new Date(now()).getTime(),
      tickAmount: 7,
      labels: { show: false },
      axisBorder: { show: false },
      axisTicks: { show: false },
    },
    yaxis: {
      show: false,
      min: 0,
      max: 100,
      tickAmount: 5,
    },
    markers: {
      size: markerSizes.length > 0 ? markerSizes : 10,
      strokeWidth: 1.5,
      strokeColors: strokeColor,
      hover: { sizeOffset: 4 },
    },
    annotations: {
      yaxis: [{
        y: 66,
        y2: 100,
        fillColor: bandColor,
        borderColor: 'transparent',
      }],
    },
  };

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
    color: theme.palette.text?.tertiary,
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
    width: CHART_HEIGHT,
    left: -12,
  };

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

  return (
    <Card title={title}>
      <div style={containerStyle}>
        <div style={{ height: CHART_HEIGHT }}>
          <Chart
            options={options}
            series={series as ApexAxisChartSeries}
            type="scatter"
            width="100%"
            height="100%"
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
    </Card>
  );
};

export default PirThreatMap;
