import React, { Suspense, useMemo, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useNavigate } from 'react-router';
import { Box, Skeleton, Stack, Typography } from '@mui/material';
import { useTheme } from '@mui/material/styles';
import { ApexOptions } from 'apexcharts';
import Card from '@common/card/Card';
import Chart from '@components/common/charts/Chart';
import { useFormatter } from '../../../../components/i18n';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { truncate } from '../../../../utils/String';
import type { Theme } from '../../../../components/Theme';
import SourcePeriodSelect from './SourcePeriodSelect';
import { buildOverlapHeatmapSeries, escapeHtml, REFERENCE_SCORECARD_PERIOD, ScorecardPeriod } from './sourceIntelligenceUtils';
import { SourcesOverlapQuery } from './__generated__/SourcesOverlapQuery.graphql';

export const sourcesOverlapQuery = graphql`
  query SourcesOverlapQuery($period: SourceScorecardPeriod, $first: Int) {
    sourceOverlap(period: $period, first: $first) {
      period
      computed_at
      sources {
        id
        name
        source_kind
      }
      cells {
        source_a
        source_b
        shared_count
        share_a
        share_b
        jaccard
      }
    }
  }
`;

const MAX_OVERLAP_SOURCES = 25;
// Characters of a source name that fit the 180 px of a rotated column label
const MAX_COLUMN_LABEL_LENGTH = 34;

interface SourcesOverlapMatrixProps {
  queryRef: PreloadedQuery<SourcesOverlapQuery>;
}

const SourcesOverlapMatrix = ({ queryRef }: SourcesOverlapMatrixProps) => {
  const { t_i18n, rd } = useFormatter();
  const theme = useTheme<Theme>();
  const navigate = useNavigate();
  const { sourceOverlap } = usePreloadedQuery(sourcesOverlapQuery, queryRef);
  const { sources, cells } = sourceOverlap;
  const series = useMemo(() => buildOverlapHeatmapSeries(sources, cells), [sources, cells]);

  const options: ApexOptions = useMemo(() => ({
    chart: {
      type: 'heatmap',
      background: 'transparent',
      foreColor: theme.palette.text.secondary,
      toolbar: { show: false },
      events: {
        dataPointSelection: (_event, _chart, { seriesIndex }) => {
          // Series are reversed (bottom-up), the clicked row is the source to open
          const row = sources[sources.length - 1 - seriesIndex];
          if (row) navigate(`/dashboard/integrations/sources/source/${row.id}`);
        },
      },
    },
    theme: { mode: theme.palette.mode },
    dataLabels: { enabled: sources.length <= 12, style: { fontSize: '10px' }, formatter: (value) => (value === null ? '' : `${value}`) },
    stroke: { colors: [theme.palette.background.paper], width: 1 },
    legend: { show: false },
    // The chart trims a rotated label to the height of the label area, which always cuts the longest one: only a name
    // too long for that area is shortened, the tooltip of a cell names both sources in full
    xaxis: {
      labels: { rotate: -45, trim: false, maxHeight: 180, formatter: (value: string) => truncate(value, MAX_COLUMN_LABEL_LENGTH) },
      tooltip: { enabled: false },
    },
    yaxis: { labels: { maxWidth: 180 } },
    tooltip: {
      theme: theme.palette.mode,
      custom: ({ seriesIndex, dataPointIndex, w }) => {
        const serie = w.config.series[seriesIndex];
        const point = serie?.data?.[dataPointIndex];
        if (!point || point.y === null) return '';
        return `<div style="padding: 8px 10px">${escapeHtml(t_i18n('Share of'))} <b>${escapeHtml(serie.name)}</b> ${escapeHtml(t_i18n('also asserted by'))} <b>${escapeHtml(point.x)}</b>: ${escapeHtml(point.y)} %<br/>${escapeHtml(t_i18n('Shared objects'))}: ${escapeHtml(point.sharedCount)}</div>`;
      },
    },
    plotOptions: {
      heatmap: {
        enableShades: false,
        colorScale: {
          // The chart writes every value in white unless its range names a colour: the pale ranges take the text
          // colours and the saturated ones the card colour, so that the values read in both themes
          ranges: [
            { from: 0, to: 0, color: theme.palette.background.accent, foreColor: theme.palette.text.secondary, name: '0 %' },
            { from: 0.01, to: 25, color: theme.palette.primary.light, foreColor: theme.palette.text.primary, name: '< 25 %' },
            { from: 25.01, to: 50, color: theme.palette.primary.main, foreColor: theme.palette.background.paper, name: '25 - 50 %' },
            { from: 50.01, to: 90, color: theme.palette.warn.main, foreColor: theme.palette.background.paper, name: '50 - 90 %' },
            { from: 90.01, to: 100, color: theme.palette.error.main, foreColor: theme.palette.background.paper, name: '> 90 %' },
          ],
        },
      },
    },
  }), [theme, sources, navigate]);

  if (sources.length < 2) {
    return (
      <Stack gap={0.5} sx={{ padding: 2 }} data-testid="source-overlap-empty">
        <Typography variant="body2">{t_i18n('The overlap appears once two sources have scorecards.')}</Typography>
        <Typography variant="caption" sx={{ color: theme.palette.text.secondary }}>
          {t_i18n('It compares the objects each source asserted in the period, so that redundant sources stand out.')}
        </Typography>
      </Stack>
    );
  }
  return (
    <Box data-testid="source-overlap-matrix">
      <Typography variant="body2" sx={{ color: theme.palette.text.secondary }}>
        {t_i18n('Each cell is the share of the objects of the row source that the column source also asserted. Above 90 percent, the row source brings almost nothing the column source does not.')}
      </Typography>
      {sourceOverlap.computed_at && (
        <Typography variant="caption" component="p" sx={{ color: theme.palette.text.secondary, marginTop: 0, marginBottom: 1 }}>
          {t_i18n('Computed {time}', { values: { time: rd(sourceOverlap.computed_at) } })}
        </Typography>
      )}
      <Box sx={{ height: Math.max(360, 28 * sources.length + 160) }}>
        <Chart options={options} series={series} type="heatmap" width="100%" height="100%" />
      </Box>
    </Box>
  );
};

const SourcesOverlap = () => {
  const { t_i18n } = useFormatter();
  const [period, setPeriod] = useState<ScorecardPeriod>(REFERENCE_SCORECARD_PERIOD);
  const queryRef = useQueryLoading<SourcesOverlapQuery>(sourcesOverlapQuery, { period, first: MAX_OVERLAP_SOURCES });
  return (
    <Card
      title={t_i18n('Overlap between sources')}
      action={(
        <Stack direction="row" gap={1} alignItems="center">
          <SourcePeriodSelect value={period} onChange={setPeriod} />
        </Stack>
      )}
    >
      {queryRef && (
        <Suspense fallback={<Skeleton variant="rounded" height={360} aria-hidden />}>
          <SourcesOverlapMatrix queryRef={queryRef} />
        </Suspense>
      )}
    </Card>
  );
};

export default SourcesOverlap;
