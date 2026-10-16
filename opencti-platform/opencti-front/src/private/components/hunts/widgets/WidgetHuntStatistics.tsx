import React, { ReactNode, Suspense, useMemo } from 'react';
import { PreloadedQuery, usePreloadedQuery } from 'react-relay';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetVerticalBars from '../../../../components/dashboard/WidgetVerticalBars';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useFormatter } from '../../../../components/i18n';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { huntHasTimeSeries, huntHitsSeries, huntHitsTickAmount, huntStatisticsQuery } from '../HuntStatistics';
import { HuntStatisticsQuery } from '../__generated__/HuntStatisticsQuery.graphql';

// Runs per platform and verdicts are standard widgets on the Hunt-Run entity type: this one sums the hits of the runs
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
  interval: string;
  queryRef: PreloadedQuery<HuntStatisticsQuery>;
}

const Content = ({ interval, queryRef }: ContentProps) => {
  const { t_i18n } = useFormatter();
  const { huntStatistics: statistics } = usePreloadedQuery(huntStatisticsQuery, queryRef);
  return huntHasTimeSeries(statistics)
    ? <WidgetVerticalBars series={huntHitsSeries(statistics, t_i18n)} interval={interval} hasLegend tickAmount={huntHitsTickAmount(statistics.hits_over_time.length)} />
    : <WidgetNoData />;
};

interface WidgetHuntStatisticsProps {
  title?: string | null;
  startDate?: string | null;
  endDate?: string | null;
  popover?: ReactNode;
}

const WidgetHuntStatistics = ({ title, startDate, endDate, popover }: WidgetHuntStatisticsProps) => {
  const { t_i18n } = useFormatter();
  const variables = useMemo(() => huntWidgetVariables(startDate, endDate), [startDate, endDate]);
  const queryRef = useQueryLoading<HuntStatisticsQuery>(huntStatisticsQuery, variables);
  return (
    <WidgetContainer title={title || t_i18n('Hunt hits over time')} action={popover}>
      <div style={{ height: '100%' }} data-testid="widget-hunt-hits-over-time">
        {queryRef ? (
          <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
            <Content interval={variables.interval} queryRef={queryRef} />
          </Suspense>
        ) : <Loader variant={LoaderVariant.inElement} />}
      </div>
    </WidgetContainer>
  );
};

export default WidgetHuntStatistics;
