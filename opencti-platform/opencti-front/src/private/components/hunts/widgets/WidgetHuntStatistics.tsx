import React, { ReactNode, Suspense, useMemo } from 'react';
import { PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useTheme } from '@mui/styles';
import type { Theme } from '../../../../components/Theme';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetVerticalBars from '../../../../components/dashboard/WidgetVerticalBars';
import WidgetHorizontalBars from '../../../../components/dashboard/WidgetHorizontalBars';
import WidgetDonut from '../../../../components/dashboard/WidgetDonut';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useFormatter } from '../../../../components/i18n';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { huntHasTimeSeries, huntHitsSeries, huntHitsTickAmount, huntPlatformSeries, huntStatisticsQuery, huntVerdictData } from '../HuntStatistics';
import { HuntStatisticsQuery } from '../__generated__/HuntStatisticsQuery.graphql';

export const HUNT_WIDGET_TYPES = ['hunt-hits-over-time', 'hunt-runs-per-platform', 'hunt-verdict-distribution'] as const;
export type HuntWidgetType = typeof HUNT_WIDGET_TYPES[number];

export const HUNT_WIDGET_TITLES: Record<HuntWidgetType, string> = {
  'hunt-hits-over-time': 'Hunt hits over time',
  'hunt-runs-per-platform': 'Hunt runs per platform',
  'hunt-verdict-distribution': 'Hunt verdict distribution',
};

const DAY_IN_MS = 24 * 60 * 60 * 1000;
const DEFAULT_PERIOD_DAYS = 30;

const huntWidgetInterval = (days: number) => {
  if (days <= 31) return 'day';
  if (days <= 120) return 'week';
  return 'month';
};

// The statistics of every hunt the user can see, over the period of the dashboard (the last 30 days without one)
export const huntWidgetVariables = (startDate?: string | null, endDate?: string | null, now: Date = new Date()) => {
  const end = endDate ? new Date(endDate) : now;
  const start = startDate ? new Date(startDate) : new Date(end.getTime() - DEFAULT_PERIOD_DAYS * DAY_IN_MS);
  return {
    huntId: null,
    startDate: start.toISOString(),
    endDate: end.toISOString(),
    interval: huntWidgetInterval((end.getTime() - start.getTime()) / DAY_IN_MS),
  };
};

interface ContentProps {
  type: HuntWidgetType;
  interval: string;
  queryRef: PreloadedQuery<HuntStatisticsQuery>;
}

const Content = ({ type, interval, queryRef }: ContentProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const { huntStatistics: statistics } = usePreloadedQuery(huntStatisticsQuery, queryRef);
  if (type === 'hunt-hits-over-time') {
    return huntHasTimeSeries(statistics)
      ? <WidgetVerticalBars series={huntHitsSeries(statistics, t_i18n)} interval={interval} hasLegend tickAmount={huntHitsTickAmount(statistics.hits_over_time.length)} />
      : <WidgetNoData />;
  }
  if (type === 'hunt-runs-per-platform') {
    return statistics.runs_per_platform.length > 0
      ? <WidgetHorizontalBars series={huntPlatformSeries(statistics, t_i18n)} distributed />
      : <WidgetNoData />;
  }
  const verdicts = huntVerdictData(statistics, t_i18n, theme);
  return verdicts.length > 0 ? <WidgetDonut data={verdicts} groupBy="verdict" /> : <WidgetNoData />;
};

interface WidgetHuntStatisticsProps {
  type: HuntWidgetType;
  title?: string | null;
  startDate?: string | null;
  endDate?: string | null;
  popover?: ReactNode;
}

const WidgetHuntStatistics = ({ type, title, startDate, endDate, popover }: WidgetHuntStatisticsProps) => {
  const { t_i18n } = useFormatter();
  const variables = useMemo(() => huntWidgetVariables(startDate, endDate), [startDate, endDate]);
  const queryRef = useQueryLoading<HuntStatisticsQuery>(huntStatisticsQuery, variables);
  return (
    <WidgetContainer title={title || t_i18n(HUNT_WIDGET_TITLES[type])} action={popover}>
      <div style={{ height: '100%' }} data-testid={`widget-${type}`}>
        {queryRef ? (
          <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
            <Content type={type} interval={variables.interval} queryRef={queryRef} />
          </Suspense>
        ) : <Loader variant={LoaderVariant.inElement} />}
      </div>
    </WidgetContainer>
  );
};

export default WidgetHuntStatistics;
