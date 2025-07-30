import React, { FunctionComponent } from 'react';
import { PreloadedQuery, usePreloadedQuery } from 'react-relay';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetVerticalBars from '../../../../components/dashboard/WidgetVerticalBars';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { FilterGroup as RelayFilterGroup, Filter as RelayFilter, MetricsWeeklyQuery } from './__generated__/MetricsWeeklyQuery.graphql';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { wauDataQuery } from './MetricsWeekly';
import { useFormatter } from '../../../../components/i18n';
/**
 * This file exports a Chart widget showing unique user activity over a given
 * number of weeks. Defaults to a 12-week rolling range, monday start-of-week.
 */

type auditsDistributionParameters = {
  field: string,
  startDate: string,
  endDate: string,
  filters: RelayFilterGroup | null | undefined,
};

interface MetricsWeeklyChartComponentProps {
  queryRef: PreloadedQuery<MetricsWeeklyQuery>,
  dateRanges: auditsDistributionParameters[]
}

interface MetricsWeeklyChartProps {
  variant: string,
  startDate: string | null,
  endDate: string | null,
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

const MetricsWeeklyChartComponent: FunctionComponent<MetricsWeeklyChartComponentProps> = ({
  queryRef,
  dateRanges,
}) => {
  const data = usePreloadedQuery<MetricsWeeklyQuery>(
    wauDataQuery,
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
          name: t_i18n('Weekly activity count'),
          data: widgetData,
        }]}
        interval={'week'}
        withExport={false}
        readonly={false}
      />
    );
  }
  return <WidgetNoData />;
};

const MetricsWeeklyChart: React.FC<MetricsWeeklyChartProps> = ({
  parameters,
  variant,
  startDate,
  endDate,
  dataSelection,
}) => {
  const { t_i18n } = useFormatter();
  const now = new Date();
  const weeks = 12;
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
      rangeEnd.setDate(rangeEnd.getDate() + 6);
      rangeEnd.setHours(23, 59, 59, 999);

      distributionParameters.push({
        field: 'user_id',
        startDate: rangeStart.toISOString(),
        endDate: rangeEnd.toISOString(),
        filters,
      });

      current.setDate(current.getDate() + 7);
    }
  } else {
    for (let i = weeks; i > 0; i -= 1) {
      const start = new Date(now);
      const end = new Date(now);

      start.setDate(now.getDate() - i * 7 + 1);
      start.setHours(0, 0, 0, 0);

      if (i === 1) {
        end.setHours(23, 59, 59, 999);
      } else {
        end.setDate(now.getDate() - (i - 1) * 7);
        end.setHours(23, 59, 59, 999);
      }

      distributionParameters.push({
        field: 'user_id',
        startDate: start.toISOString(),
        endDate: end.toISOString(),
        filters,
      });
    }
  }

  const queryRef = useQueryLoading<MetricsWeeklyQuery>(
    wauDataQuery,
    { distributionParameters },
  );

  return (
    <WidgetContainer
      title={t_i18n(parameters?.title?.trim()) || t_i18n('Weekly activity chart')}
      variant={variant}
    >
      {queryRef ? (
        <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <MetricsWeeklyChartComponent
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

export default MetricsWeeklyChart;
