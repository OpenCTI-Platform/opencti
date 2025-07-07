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
 * number of weeks. Defaults to a 6-week rolling range, monday start-of-week.
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
  startDate?: string | null,
  endDate?: string | null,
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

const MetricsWeeklyChartComponent: FunctionComponent<
MetricsWeeklyChartComponentProps
> = ({
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
  const distributionParameters: auditsDistributionParameters[] = [];
  const { t_i18n } = useFormatter();
  const filters = convertToRelayFilterGroup(dataSelection?.[0]?.filters);

  console.log('endDate: ', endDate);
  console.log('startDate: ', startDate);

  if (filters) {
    const typedFilters = filters as RelayFilterGroup;
    console.log('Typed Filters:', JSON.stringify(typedFilters, null, 2));
  } else {
    console.log('No filters provided');
  }

  if (startDate && endDate) {
    distributionParameters.push({
      field: 'user_id',
      startDate,
      endDate,
      filters,
    });
  } else {
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const dayOfWeek = today.getDay();
    const diffToMonday = dayOfWeek === 0 ? 6 : dayOfWeek - 1;
    const startOfWeek = new Date(today);
    startOfWeek.setDate(today.getDate() - diffToMonday);

    for (let i = 0; i < 6; i += 1) {
      const weekStart = new Date(startOfWeek);
      weekStart.setDate(startOfWeek.getDate() - 1 * 7);

      const weekEnd = new Date(weekStart);
      weekEnd.setDate(weekStart.getDate() + 6);
      weekEnd.setHours(23, 59, 59, 999);

      distributionParameters.push({
        field: 'user_id',
        startDate: weekStart.toISOString(),
        endDate: weekEnd.toISOString(),
        filters,
      });
    }
    distributionParameters.reverse();
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
