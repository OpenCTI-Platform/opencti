import { PreloadedQuery, usePreloadedQuery } from 'react-relay';
import React, { FunctionComponent } from 'react';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetVerticalBars from '../../../../components/dashboard/WidgetVerticalBars';
import { FilterGroup as RelayFilterGroup, Filter as RelayFilter, MetricsMonthlyQuery } from './__generated__/MetricsMonthlyQuery.graphql';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { mauDataQuery } from './MetricsMonthly';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import { useFormatter } from '../../../../components/i18n';

/**
 * This file exports a Chart widget showing unique user activity over a given
 * number of months. Defaults to a 6-month rolling range.
 */

type auditsDistributionParameters = {
  field: string,
  startDate: string,
  endDate: string,
  filters: RelayFilterGroup | null | undefined,
};

interface MetricsMonthlyChartComponentProps {
  queryRef: PreloadedQuery<MetricsMonthlyQuery>,
  dateRanges: auditsDistributionParameters[],
}

interface MetricsMonthlyChartProps {
  variant: string,
  endDate: string | null,
  startDate: string | null,
  parameters: {
    title?: string;
  }
  dataSelection?: {
    filters?: unknown;
  }[];
}

function convertToRelayFilterGroup(input?: any): RelayFilterGroup | undefined {
  if (!input) return undefined;
  return {
    mode: input.mode,
    filters: input.filters.map((f: { key: any; values: any; }) => ({
      ...f,
      key: Array.isArray(f.key) ? f.key : [f.key],
      values: f.values,
    })) as readonly RelayFilter[],
    filterGroups: input.filterGroups ?? [],
  };
}

const MetricsMonthlyChartComponent: FunctionComponent<
MetricsMonthlyChartComponentProps
> = ({
  queryRef,
  dateRanges,
}) => {
  const data = usePreloadedQuery<MetricsMonthlyQuery>(
    mauDataQuery,
    queryRef,
  );

  const { t_i18n } = useFormatter();

  if (data.auditsMultiDistribution) {
    // Create the series data for the Chart widget
    const widgetData = data.auditsMultiDistribution.map((selection, i: number) => ({
      x: dateRanges[i].startDate,
      y: selection?.data?.length ?? 0,
    }));

    return (
      <WidgetVerticalBars
        series={[{
          name: t_i18n('Monthly activity count'),
          data: widgetData,
        }]}
        interval={'month'}
        withExport={false}
        readonly={false}
      />
    );
  }
  return <WidgetNoData />;
};

const MetricsMonthlyChart: React.FC<MetricsMonthlyChartProps> = ({
  parameters,
  variant,
  endDate,
  startDate,
  dataSelection,
}) => {
  const { t_i18n } = useFormatter();
  const now = new Date();
  const months = 6;
  now.setHours(23, 59, 59, 999);

  const distributionParameters: auditsDistributionParameters[] = [];
  const filters = convertToRelayFilterGroup(dataSelection?.[0]?.filters);

  if (startDate && endDate) {
    const start = new Date(startDate);
    const end = new Date(endDate);
    start.setHours(0, 0, 0, 0);
    end.setHours(23, 59, 59, 999);

    const current = new Date(start);
    while (current <= end) {
      const rangeStart = new Date(current);
      const rangeEnd = new Date(current);

      rangeEnd.setMonth(rangeEnd.getMonth() + 1);
      rangeEnd.setDate(0);
      rangeEnd.setHours(23, 59, 59, 999);

      distributionParameters.push({
        field: 'user_id',
        startDate: rangeStart.toISOString(),
        endDate: rangeEnd.toISOString(),
        filters,
      });

      current.setMonth(current.getMonth() + 1);
    }
  } else {
    // Create rolling date ranges for specified number of months
    for (let i = months; i > 0; i -= 1) {
      // Since setMonth modifies in place, create new Dates from `now`
      const start = new Date(now);
      const end = new Date(now);

      // Date range is `i` months ago to `i+1` months ago
      start.setMonth(now.getMonth() - i);
      end.setMonth(now.getMonth() - i + 1);

      distributionParameters.push({
        field: 'user_id',
        startDate: start.toISOString(),
        endDate: end.toISOString(),
        filters,
      });
    }
  }

  const queryRef = useQueryLoading<MetricsMonthlyQuery>(
    mauDataQuery,
    { distributionParameters },
  );

  return (
    <WidgetContainer
      title={t_i18n(parameters?.title?.trim()) ?? t_i18n('Monthly activity chart')}
      variant={variant}
    >
      {queryRef ? (
        <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <MetricsMonthlyChartComponent
            queryRef={queryRef}
            dateRanges={distributionParameters}
          />
        </React.Suspense>
      ) : (
        <Loader variant={LoaderVariant.inElement} />
      )}
    </WidgetContainer>
  );
};

export default MetricsMonthlyChart;
