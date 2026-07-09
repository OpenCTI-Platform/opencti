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

import React, { CSSProperties, FunctionComponent, ReactNode, useCallback, useMemo, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import ApexCharts from 'apexcharts';
import { AuditsMultiVerticalBarsTimeSeriesQuery } from '@components/common/audits/__generated__/AuditsMultiVerticalBarsTimeSeriesQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import { monthsAgo, now } from '../../../../utils/Time';
import { normalizeFilterGroupForBackend, removeEntityTypeAllFromFilterGroup } from '../../../../utils/filters/filtersUtils';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetVerticalBars from '../../../../components/dashboard/WidgetVerticalBars';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import type { WidgetDataSelection, WidgetHost, WidgetParameters } from '../../../../utils/widget/widget';
import type { DashboardConfig } from '../../../../components/dashboard/dashboard-types';
import AuditsWidgetRenderContent from '../../../../components/dashboard/AuditsWidgetRenderContent';
import { getWidgetInterval } from '../../../../utils/widget/widgetUtils';

const auditsMultiVerticalBarsTimeSeriesQuery = graphql`
  query AuditsMultiVerticalBarsTimeSeriesQuery(
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

interface AuditsMultiVerticalBarsComponentProps {
  queryRef: PreloadedQuery<AuditsMultiVerticalBarsTimeSeriesQuery>;
  dataSelection: WidgetDataSelection[];
  interval?: string;
  isStacked?: boolean;
  hasLegend?: boolean;
  onMounted: (chart: ApexCharts) => void;
}

const AuditsMultiVerticalBarsComponent: FunctionComponent<AuditsMultiVerticalBarsComponentProps> = ({
  queryRef,
  dataSelection,
  interval,
  isStacked,
  hasLegend,
  onMounted,
}) => {
  const { t_i18n } = useFormatter();
  const data = usePreloadedQuery<AuditsMultiVerticalBarsTimeSeriesQuery>(
    auditsMultiVerticalBarsTimeSeriesQuery,
    queryRef,
  );
  type TimeSeriesEntry = NonNullable<
    NonNullable<
      NonNullable<AuditsMultiVerticalBarsTimeSeriesQuery['response']['auditsMultiTimeSeries']>[number]
    >['data']
  >[number];

  if (data.auditsMultiTimeSeries) {
    return (
      <WidgetVerticalBars
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

interface AuditsMultiVerticalBarsProps {
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

const AuditsMultiVerticalBars: FunctionComponent<AuditsMultiVerticalBarsProps> = ({
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
  const fallbackDates = useMemo(() => ({
    start: monthsAgo(12),
    end: now(),
  }), []);

  const buildQueryVariables = useCallback((resolvedDataSelection: WidgetDataSelection[]): AuditsMultiVerticalBarsTimeSeriesQuery['variables'] => {
    const timeSeriesParameters = resolvedDataSelection.map((selection) => {
      return {
        field:
          selection.date_attribute && selection.date_attribute.length > 0
            ? selection.date_attribute
            : 'timestamp',
        types: ['History', 'Activity'],
        filters: normalizeFilterGroupForBackend(removeEntityTypeAllFromFilterGroup(selection.filters)),
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

  const { resolvedDataSelection, isMissingHostEntity, isMissingSavedFilters, isPreviewMode, queryRef } = useDashboardViz<AuditsMultiVerticalBarsTimeSeriesQuery>({
    perspective: 'audits',
    dataSelection,
    host,
    refreshRate,
    query: auditsMultiVerticalBarsTimeSeriesQuery,
    config,
    parameters,
    buildQueryVariables,
  });

  return (
    <WidgetContainer
      padding="small"
      height={height}
      title={parameters.title ?? t_i18n('Activity and history')}
      variant={variant}
      chart={chart}
      action={popover}
      showPreviewTag={isPreviewMode}
    >
      <AuditsWidgetRenderContent
        isMissingHostEntity={isMissingHostEntity}
        isMissingSavedFilters={isMissingSavedFilters}
        queryRef={queryRef}
        host={host}
      >
        <AuditsMultiVerticalBarsComponent
          queryRef={queryRef!}
          dataSelection={resolvedDataSelection}
          interval={parameters.interval ?? undefined}
          isStacked={parameters.stacked ?? undefined}
          hasLegend={parameters.legend ?? undefined}
          onMounted={setChart}
        />
      </AuditsWidgetRenderContent>
    </WidgetContainer>
  );
};

export default AuditsMultiVerticalBars;
