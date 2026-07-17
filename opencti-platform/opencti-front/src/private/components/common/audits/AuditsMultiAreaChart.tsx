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

import React, { CSSProperties, FunctionComponent, ReactNode, Suspense, useCallback, useEffect, useMemo, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import ApexCharts from 'apexcharts';
import { AuditsMultiAreaChartTimeSeriesQuery } from '@components/common/audits/__generated__/AuditsMultiAreaChartTimeSeriesQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import { monthsAgo, now } from '../../../../utils/Time';
import useGranted, { SETTINGS_SECURITYACTIVITY, SETTINGS_SETACCESSES, VIRTUAL_ORGANIZATION_ADMIN } from '../../../../utils/hooks/useGranted';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import { normalizeFilterGroupForBackend, removeEntityTypeAllFromFilterGroup } from '../../../../utils/filters/filtersUtils';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetMultiAreas from '../../../../components/dashboard/WidgetMultiAreas';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import WidgetNoHostEntity from '../../../../components/dashboard/WidgetNoHostEntity';
import WidgetAccessDenied from '../../../../components/dashboard/WidgetAccessDenied';
import { getWidgetInterval, showEstimationWarningForUniqCount, UNIQUE_COUNT_ESTIMATION_WARNING } from '../../../../utils/widget/widgetUtils';
import type { WidgetDataSelection, WidgetHost, WidgetMultiTimeSeries, WidgetParameters } from '../../../../utils/widget/widget';
import type { DashboardConfig } from '../../../../components/dashboard/dashboard-types';

const auditsMultiAreaChartTimeSeriesQuery = graphql`
  query AuditsMultiAreaChartTimeSeriesQuery(
    $operation: StatsOperation!
    $startDate: DateTime!
    $endDate: DateTime!
    $interval: String!
    $timeSeriesParameters: [AuditsTimeSeriesParameters]
  ) {
    auditsMultiTimeSeries(
      operation: $operation
      startDate: $startDate
      endDate: $endDate
      interval: $interval
      timeSeriesParameters: $timeSeriesParameters
    ) {
      data {
        date
        value
      }
    }
  }
`;

interface AuditsMultiAreaChartComponentProps {
  queryRef: PreloadedQuery<AuditsMultiAreaChartTimeSeriesQuery>;
  dataSelection: WidgetDataSelection[];
  interval?: string;
  isStacked?: boolean;
  hasLegend?: boolean;
  onMounted: (chart: ApexCharts) => void;
  onShowWarning: (show: boolean) => void;
}

type TimeSeriesEntry = NonNullable<
  NonNullable<
    NonNullable<AuditsMultiAreaChartTimeSeriesQuery['response']['auditsMultiTimeSeries']>[number]
  >['data']
>[number];

const AuditsMultiAreaChartComponent: FunctionComponent<AuditsMultiAreaChartComponentProps> = ({
  queryRef,
  dataSelection,
  interval,
  isStacked,
  hasLegend,
  onMounted,
  onShowWarning,
}) => {
  const { t_i18n } = useFormatter();
  const data = usePreloadedQuery<AuditsMultiAreaChartTimeSeriesQuery>(
    auditsMultiAreaChartTimeSeriesQuery,
    queryRef,
  );

  useEffect(() => {
    const warningData: WidgetMultiTimeSeries[] = (data.auditsMultiTimeSeries ?? []).map((series) => ({
      data: (series?.data ?? []).flatMap((entry) => (entry ? [{ date: entry.date, value: entry.value }] : [])),
    }));
    onShowWarning(showEstimationWarningForUniqCount(dataSelection, warningData));
  }, [dataSelection, data.auditsMultiTimeSeries, onShowWarning]);

  if (data.auditsMultiTimeSeries) {
    return (
      <WidgetMultiAreas
        series={dataSelection.map((selection, i) => ({
          name: selection.label || t_i18n('Number of history entries'),
          data: (data.auditsMultiTimeSeries?.[i]?.data ?? [])
            .filter((entry): entry is NonNullable<TimeSeriesEntry> => entry != null)
            .map((entry) => ({
              x: new Date(entry.date),
              y: entry.value,
            })),
        }))}
        interval={interval}
        isStacked={isStacked}
        hasLegend={hasLegend}
        onMounted={onMounted}
      />
    );
  }
  return <WidgetNoData />;
};

interface AuditsMultiAreaChartProps {
  variant?: string;
  height?: CSSProperties['height'];
  startDate?: string | null;
  endDate?: string | null;
  dataSelection: WidgetDataSelection[];
  parameters?: WidgetParameters;
  config: DashboardConfig;
  refreshRate?: number | null;
  popover?: ReactNode;
  host?: WidgetHost;
}

const AuditsMultiAreaChart: FunctionComponent<AuditsMultiAreaChartProps> = ({
  variant,
  height,
  startDate,
  endDate,
  dataSelection,
  parameters = {},
  config,
  refreshRate = null,
  popover,
  host,
}) => {
  const { t_i18n } = useFormatter();
  const [chart, setChart] = useState<ApexCharts>();
  const [showWarning, setShowWarning] = useState(false);
  const warning = showWarning ? t_i18n(UNIQUE_COUNT_ESTIMATION_WARNING) : undefined;

  const fallbackDates = useMemo(() => ({
    start: monthsAgo(12),
    end: now(),
  }), []);

  const buildQueryVariables = useCallback((resolvedDataSelection: WidgetDataSelection[]): AuditsMultiAreaChartTimeSeriesQuery['variables'] => {
    const timeSeriesParameters = resolvedDataSelection.map((selection) => {
      return {
        field:
          selection.date_attribute && selection.date_attribute.length > 0
            ? selection.date_attribute
            : 'timestamp',
        types: ['History', 'Activity'],
        filters: normalizeFilterGroupForBackend(removeEntityTypeAllFromFilterGroup(selection.filters)),
        countField: selection.attribute,
        unique: selection.unique,
      };
    });

    return {
      operation: 'count' as const,
      startDate: startDate ?? fallbackDates.start,
      endDate: endDate ?? fallbackDates.end,
      interval: getWidgetInterval(parameters),
      timeSeriesParameters,
    };
  }, [startDate, endDate, fallbackDates, parameters.interval]);

  const { resolvedDataSelection, isMissingHostEntity, isPreviewMode, queryRef } = useDashboardViz<AuditsMultiAreaChartTimeSeriesQuery>({
    perspective: 'audits',
    dataSelection,
    host,
    refreshRate,
    query: auditsMultiAreaChartTimeSeriesQuery,
    config,
    parameters,
    buildQueryVariables,
  });

  const isGrantedToSettings = useGranted([SETTINGS_SETACCESSES, SETTINGS_SECURITYACTIVITY, VIRTUAL_ORGANIZATION_ADMIN]);
  const isEnterpriseEdition = useEnterpriseEdition();

  const renderContent = () => {
    if (isMissingHostEntity) {
      return <WidgetNoHostEntity host={host} />;
    }

    if (!isGrantedToSettings || !isEnterpriseEdition) {
      return <WidgetAccessDenied />;
    }

    if (!queryRef) {
      return <Loader variant={LoaderVariant.inElement} />;
    }

    return (
      <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
        <AuditsMultiAreaChartComponent
          queryRef={queryRef}
          dataSelection={resolvedDataSelection}
          interval={parameters.interval ?? undefined}
          isStacked={parameters.stacked ?? undefined}
          hasLegend={parameters.legend ?? undefined}
          onMounted={setChart}
          onShowWarning={setShowWarning}
        />
      </Suspense>
    );
  };

  return (
    <WidgetContainer
      padding="small"
      height={height}
      title={parameters.title ?? t_i18n('Activity and history')}
      variant={variant}
      chart={chart}
      action={popover}
      showPreviewTag={isPreviewMode}
      warning={warning}
    >
      {renderContent()}
    </WidgetContainer>
  );
};

export default AuditsMultiAreaChart;
