import React, { ReactNode, Suspense, useMemo, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import Grid from '@mui/material/Grid';
import { useTheme } from '@mui/styles';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@filigran/design-system';
import { useFormatter } from '../../../components/i18n';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import CardStatistic from '../../../components/common/card/CardStatistic';
import WidgetContainer from '../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../components/dashboard/WidgetNoData';
import WidgetVerticalBars from '../../../components/dashboard/WidgetVerticalBars';
import WidgetHorizontalBars from '../../../components/dashboard/WidgetHorizontalBars';
import WidgetDonut from '../../../components/dashboard/WidgetDonut';
import Loader, { LoaderVariant } from '../../../components/Loader';
import type { Theme } from '../../../components/Theme';
import { HuntStatisticsQuery } from './__generated__/HuntStatisticsQuery.graphql';
import { HUNT_PLATFORM_INTERNET, huntVerdictLabel } from './hunt-utils';

export const huntStatisticsQuery = graphql`
  query HuntStatisticsQuery($huntId: ID, $startDate: DateTime, $endDate: DateTime, $interval: String) {
    huntStatistics(huntId: $huntId, startDate: $startDate, endDate: $endDate, interval: $interval) {
      runs_count
      completed_runs_count
      failed_runs_count
      autonomous_runs_count
      hits_total
      true_positive_count
      benign_count
      inconclusive_count
      pending_count
      last_run_at
      hits_over_time {
        date
        value
      }
      runs_over_time {
        date
        value
      }
      runs_per_platform {
        label
        value
      }
      verdict_distribution {
        label
        value
      }
    }
  }
`;

export type HuntStatisticsPeriod = '7d' | '30d' | '90d' | '365d';

const PERIODS: Record<HuntStatisticsPeriod, { days: number; interval: string; label: string }> = {
  '7d': { days: 7, interval: 'day', label: 'Last 7 days' },
  '30d': { days: 30, interval: 'day', label: 'Last 30 days' },
  '90d': { days: 90, interval: 'week', label: 'Last 90 days' },
  '365d': { days: 365, interval: 'month', label: 'Last year' },
};

const DAY_IN_MS = 24 * 60 * 60 * 1000;

export const huntStatisticsVariables = (huntId: string | null, period: HuntStatisticsPeriod, now: Date = new Date()) => ({
  huntId,
  startDate: new Date(now.getTime() - PERIODS[period].days * DAY_IN_MS).toISOString(),
  endDate: now.toISOString(),
  interval: PERIODS[period].interval,
});

type HuntStatisticsData = HuntStatisticsQuery['response']['huntStatistics'];
type Translate = (key: string) => string;

export const huntHitsSeries = (statistics: HuntStatisticsData, t_i18n: Translate) => [{
  name: t_i18n('Hits'),
  data: statistics.hits_over_time.map((point) => ({ x: new Date(point.date), y: point.value })),
}, {
  name: t_i18n('Runs'),
  data: statistics.runs_over_time.map((point) => ({ x: new Date(point.date), y: point.value })),
}] as ApexAxisChartSeries;

export const huntHasTimeSeries = (statistics: HuntStatisticsData) => statistics.runs_over_time.some((point) => point.value > 0);

// An empty label is a security platform the reader cannot see anymore (deleted or restricted)
const huntStatisticsPlatformLabel = (label: string, t_i18n: Translate) => {
  if (label === HUNT_PLATFORM_INTERNET) return t_i18n('Internet');
  return label.length > 0 ? label : t_i18n('Unavailable security platform');
};

export const huntPlatformSeries = (statistics: HuntStatisticsData, t_i18n: Translate) => [{
  name: t_i18n('Runs'),
  data: statistics.runs_per_platform.map((bucket) => ({ x: huntStatisticsPlatformLabel(bucket.label, t_i18n), y: bucket.value })),
}] as ApexAxisChartSeries;

// Verdict slices take the tone of their chip: red only for a true positive, the state that calls for a response, and a
// mid grey for pending in both themes (the text colour would draw it white or black)
const huntVerdictColor = (theme: Theme, verdict: string) => {
  switch (verdict) {
    case 'true_positive': return theme.palette.error.main;
    case 'benign': return theme.palette.success.main;
    case 'inconclusive': return theme.palette.warn.main;
    default: return (theme.palette.mode === 'light' ? theme.palette.common?.lightGrey : theme.palette.common?.grey) ?? theme.palette.text.secondary;
  }
};

// One label a week on a daily series longer than two weeks, instead of one per bar
export const huntHitsTickAmount = (pointCount: number) => (pointCount > 14 ? Math.ceil(pointCount / 7) : undefined);

export const huntVerdictData = (statistics: HuntStatisticsData, t_i18n: Translate, theme?: Theme) => statistics.verdict_distribution
  .filter((bucket) => bucket.value > 0)
  .map((bucket) => ({
    label: t_i18n(huntVerdictLabel(bucket.label)),
    value: bucket.value,
    ...(theme ? { entity: { color: huntVerdictColor(theme, bucket.label) } } : {}),
  }));

const WIDGET_HEIGHT = 280;

interface HuntStatisticsComponentProps {
  queryRef: PreloadedQuery<HuntStatisticsQuery>;
  interval: string;
  showWidgets: boolean;
}

const HuntStatisticsComponent = ({ queryRef, interval, showWidgets }: HuntStatisticsComponentProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n, n } = useFormatter();
  const { huntStatistics: statistics } = usePreloadedQuery(huntStatisticsQuery, queryRef);
  const truePositiveRate = statistics.completed_runs_count > 0
    ? Math.round((statistics.true_positive_count / statistics.completed_runs_count) * 100)
    : null;
  const autonomousRate = statistics.runs_count > 0
    ? Math.round((statistics.autonomous_runs_count / statistics.runs_count) * 100)
    : null;
  const hitsSeries = huntHitsSeries(statistics, t_i18n);
  const platformSeries = huntPlatformSeries(statistics, t_i18n);
  const verdicts = huntVerdictData(statistics, t_i18n, theme);
  const hasTimeSeries = huntHasTimeSeries(statistics);

  return (
    <>
      <Grid container spacing={3} sx={{ marginBottom: showWidgets ? 3 : 0 }} data-testid="hunt-statistics-kpis">
        <Grid item xs={6} md={2}>
          <CardStatistic label={t_i18n('Runs')} value={n(statistics.runs_count)} />
        </Grid>
        <Grid item xs={6} md={2}>
          <CardStatistic label={t_i18n('Hits')} value={n(statistics.hits_total)} />
        </Grid>
        <Grid item xs={6} md={2}>
          <CardStatistic label={t_i18n('True positives')} value={n(statistics.true_positive_count)} />
        </Grid>
        <Grid item xs={6} md={2}>
          <CardStatistic label={t_i18n('True positive rate')} value={truePositiveRate === null ? '-' : `${truePositiveRate}%`} />
        </Grid>
        <Grid item xs={6} md={2}>
          <CardStatistic label={t_i18n('Autonomous runs')} value={autonomousRate === null ? '-' : `${autonomousRate}%`} />
        </Grid>
        <Grid item xs={6} md={2}>
          <CardStatistic label={t_i18n('Failed runs')} value={n(statistics.failed_runs_count)} />
        </Grid>
      </Grid>
      {showWidgets && (
        <Grid container spacing={3} data-testid="hunt-statistics-widgets">
          <Grid item xs={12} md={5}>
            <WidgetContainer title={t_i18n('Hits over time')} height={WIDGET_HEIGHT} variant="inLine">
              {hasTimeSeries ? (
                <WidgetVerticalBars series={hitsSeries} interval={interval} hasLegend tickAmount={huntHitsTickAmount(statistics.hits_over_time.length)} />
              ) : <WidgetNoData />}
            </WidgetContainer>
          </Grid>
          <Grid item xs={12} md={3}>
            <WidgetContainer title={t_i18n('Runs per platform')} height={WIDGET_HEIGHT} variant="inLine">
              {statistics.runs_per_platform.length > 0 ? <WidgetHorizontalBars series={platformSeries} distributed /> : <WidgetNoData />}
            </WidgetContainer>
          </Grid>
          {/* Wide enough for the four verdicts of the legend on one line */}
          <Grid item xs={12} md={4}>
            <WidgetContainer title={t_i18n('Verdict distribution')} height={WIDGET_HEIGHT} variant="inLine">
              {verdicts.length > 0 ? <WidgetDonut data={verdicts} groupBy="verdict" /> : <WidgetNoData />}
            </WidgetContainer>
          </Grid>
        </Grid>
      )}
    </>
  );
};

interface HuntStatisticsProps {
  /** Statistics of one hunt, or of every hunt the user can see when null */
  huntId?: string | null;
  showWidgets?: boolean;
  defaultPeriod?: HuntStatisticsPeriod;
  /** Rendered before the period selector, on its row */
  action?: ReactNode;
}

const HuntStatistics = ({ huntId = null, showWidgets = true, defaultPeriod = '30d', action }: HuntStatisticsProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const [period, setPeriod] = useState<HuntStatisticsPeriod>(defaultPeriod);
  // The window is computed once per period change so the query is not refetched at every render
  const variables = useMemo(() => huntStatisticsVariables(huntId, period), [huntId, period]);
  const queryRef = useQueryLoading<HuntStatisticsQuery>(huntStatisticsQuery, variables);

  return (
    <div data-testid="hunt-statistics">
      <div style={{ display: 'flex', justifyContent: 'flex-end', alignItems: 'center', gap: theme.spacing(1), marginBottom: 12 }}>
        {action}
        <Select value={period} onValueChange={(value) => setPeriod(value as HuntStatisticsPeriod)}>
          <SelectTrigger aria-label={t_i18n('Period')} style={{ width: 180 }}>
            <SelectValue />
          </SelectTrigger>
          <SelectContent aria-label={t_i18n('Period')}>
            {(Object.keys(PERIODS) as HuntStatisticsPeriod[]).map((key) => (
              <SelectItem key={key} value={key}>{t_i18n(PERIODS[key].label)}</SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      {queryRef && (
        <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <HuntStatisticsComponent queryRef={queryRef} interval={PERIODS[period].interval} showWidgets={showWidgets} />
        </Suspense>
      )}
    </div>
  );
};

export default HuntStatistics;
