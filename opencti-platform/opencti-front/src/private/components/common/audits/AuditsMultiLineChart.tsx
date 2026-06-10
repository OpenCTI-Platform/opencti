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
import { AuditsMultiLineChartTimeSeriesQuery, FilterGroup as GqlFilterGroup } from '@components/common/audits/__generated__/AuditsMultiLineChartTimeSeriesQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import { monthsAgo, now } from '../../../../utils/Time';
import useGranted, { SETTINGS_SECURITYACTIVITY, SETTINGS_SETACCESSES, VIRTUAL_ORGANIZATION_ADMIN } from '../../../../utils/hooks/useGranted';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import { removeEntityTypeAllFromFilterGroup } from '../../../../utils/filters/filtersUtils';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetMultiLines from '../../../../components/dashboard/WidgetMultiLines';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import WidgetNoHostEntity from '../../../../components/dashboard/WidgetNoHostEntity';
import { UNIQUE_COUNT_ESTIMATION_WARNING, showEstimationWarningForUniqCount } from '../../../../utils/widget/widgetUtils';
import type { WidgetDataSelection, WidgetHost, WidgetParameters } from '../../../../utils/widget/widget';
import type { DashboardConfig } from '../../../../components/dashboard/dashboard-types';

const auditsMultiLineChartTimeSeriesQuery = graphql`
  query AuditsMultiLineChartTimeSeriesQuery(
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

interface AuditsMultiLineChartComponentProps {
  queryRef: PreloadedQuery<AuditsMultiLineChartTimeSeriesQuery>;
  dataSelection: WidgetDataSelection[];
  interval?: string;
  hasLegend?: boolean;
  onMounted: (chart: ApexCharts) => void;
  onShowWarning: (show: boolean) => void;
}

type TimeSeriesEntry = NonNullable<
  NonNullable<
    NonNullable<AuditsMultiLineChartTimeSeriesQuery['response']['auditsMultiTimeSeries']>[number]
  >['data']
>[number];

const AuditsMultiLineChartComponent: FunctionComponent<AuditsMultiLineChartComponentProps> = ({
  queryRef,
  dataSelection,
  interval,
  hasLegend,
  onMounted,
  onShowWarning,
}) => {
  const { t_i18n } = useFormatter();
  const data = usePreloadedQuery<AuditsMultiLineChartTimeSeriesQuery>(
    auditsMultiLineChartTimeSeriesQuery,
    queryRef,
  );

  useEffect(() => {
    const warningData = (data.auditsMultiTimeSeries ?? []).map((series) => ({
      data: (series?.data ?? []).flatMap((entry) => (entry ? [{ date: entry.date, value: entry.value }] : [])),
    }));
    onShowWarning(showEstimationWarningForUniqCount(dataSelection, warningData));
  }, [dataSelection, data.auditsMultiTimeSeries, onShowWarning]);

  if (data.auditsMultiTimeSeries) {
    return (
      <WidgetMultiLines
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
        hasLegend={hasLegend}
        onMounted={onMounted}
      />
    );
  }
  return <WidgetNoData />;
};

interface AuditsMultiLineChartProps {
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

const AuditsMultiLineChart: FunctionComponent<AuditsMultiLineChartProps> = ({
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
  const fallbackDates = useMemo(() => ({
    start: monthsAgo(12),
    end: now(),
  }), []);
  const warning = showWarning ? t_i18n(UNIQUE_COUNT_ESTIMATION_WARNING) : undefined;

  const buildQueryVariables = useCallback((resolvedDataSelection: WidgetDataSelection[]): AuditsMultiLineChartTimeSeriesQuery['variables'] => {
    const timeSeriesParameters = resolvedDataSelection.map((selection) => {
      return {
        field:
          selection.date_attribute && selection.date_attribute.length > 0
            ? selection.date_attribute
            : 'timestamp',
        types: ['History', 'Activity'],
        filters: removeEntityTypeAllFromFilterGroup(selection.filters ?? undefined) as unknown as GqlFilterGroup,
        countField: selection.attribute,
        unique: selection.unique,
      };
    });

    return {
      operation: 'count' as const,
      startDate: startDate ?? fallbackDates.start,
      endDate: endDate ?? fallbackDates.end,
      interval: parameters.interval ?? 'day',
      timeSeriesParameters,
    };
  }, [startDate, endDate, fallbackDates, parameters.interval]);

  const { resolvedDataSelection, isMissingHostEntity, isPreviewMode, queryRef } = useDashboardViz<AuditsMultiLineChartTimeSeriesQuery>({
    perspective: 'audits',
    dataSelection,
    host,
    refreshRate,
    query: auditsMultiLineChartTimeSeriesQuery,
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
      return (
        <div style={{ display: 'table', height: '100%', width: '100%' }}>
          <span
            style={{
              display: 'table-cell',
              verticalAlign: 'middle',
              textAlign: 'center',
            }}
          >
            {!isEnterpriseEdition
              ? t_i18n(
                  'This feature is only available in OpenCTI Enterprise Edition.',
                )
              : t_i18n('You are not authorized to see this data.')}
          </span>
        </div>
      );
    }

    if (!queryRef) {
      return <Loader variant={LoaderVariant.inElement} />;
    }

    return (
      <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
        <AuditsMultiLineChartComponent
          queryRef={queryRef}
          dataSelection={resolvedDataSelection}
          interval={parameters.interval ?? undefined}
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

export default AuditsMultiLineChart;
