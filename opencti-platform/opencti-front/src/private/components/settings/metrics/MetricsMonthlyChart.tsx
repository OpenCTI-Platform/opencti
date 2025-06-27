import { PreloadedQuery, usePreloadedQuery } from 'react-relay';
import React, { FunctionComponent } from 'react';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetMultiLines from '../../../../components/dashboard/WidgetMultiLines';
import { FilterGroup, MetricsMonthlyQuery } from './__generated__/MetricsMonthlyQuery.graphql';
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
  filters: FilterGroup | null | undefined,
};

interface MetricsMonthlyChartComponentProps {
  queryRef: PreloadedQuery<MetricsMonthlyQuery>,
  dateRanges: auditsDistributionParameters[],
}

interface MetricsMonthlyChartProps {
  variant: string,
  parameters: {
    title?: string;
  }
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
      <WidgetMultiLines
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
}) => {
  const { t_i18n } = useFormatter();
  const now = new Date();
  const months = 6;
  now.setHours(23, 59, 59, 999);
  const distributionParameters: auditsDistributionParameters[] = [];

  // Create rolling date ranges for specified number of months
  for (let i = months; i > 0; i -= 1) {
    // Since setMonth modifies in place, create new Dates from `now`
    const startDate = new Date(now);
    const endDate = new Date(now);

    // Date range is `i` months ago to `i+1` months ago
    startDate.setMonth(now.getMonth() - i);
    endDate.setMonth(now.getMonth() - i + 1);

    const filters: FilterGroup = {
      mode: 'and',
      filters: [
        {
          key: ['event_scope'],
          values: ['search', 'analyze', 'enrich', 'import', 'export', 'read', 'create', 'delete', 'download', 'disseminate', 'update'],
        },
      ],
      filterGroups: [],
    };

    distributionParameters.push({
      field: 'user_id',
      startDate: startDate.toISOString(),
      endDate: endDate.toISOString(),
      filters,
    });
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
