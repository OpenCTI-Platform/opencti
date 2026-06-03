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

import React, { CSSProperties, FunctionComponent, ReactNode, Suspense, useMemo, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import ApexCharts from 'apexcharts';
import { AuditsMultiVerticalBarsTimeSeriesQuery } from '@components/common/audits/__generated__/AuditsMultiVerticalBarsTimeSeriesQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import { monthsAgo, now } from '../../../../utils/Time';
import useGranted, { SETTINGS_SECURITYACTIVITY, SETTINGS_SETACCESSES, VIRTUAL_ORGANIZATION_ADMIN } from '../../../../utils/hooks/useGranted';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import { removeEntityTypeAllFromFilterGroup } from '../../../../utils/filters/filtersUtils';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetVerticalBars from '../../../../components/dashboard/WidgetVerticalBars';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import WidgetNoHostEntity from '../../../../components/dashboard/WidgetNoHostEntity';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import type { WidgetDataSelection, WidgetHost, WidgetParameters } from '../../../../utils/widget/widget';

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

  if (data.auditsMultiTimeSeries) {
    return (
      <WidgetVerticalBars
        series={dataSelection.map((selection, i) => ({
          name: selection.label || t_i18n('Number of history entries'),
          data: data.auditsMultiTimeSeries[i].data.map((entry) => ({
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
  popover,
  host,
}) => {
  const { t_i18n } = useFormatter();
  const [chart, setChart] = useState<ApexCharts>();
  const { resolvedDataSelection, isMissingHostEntity, isPreviewMode } = useDashboardViz({
    perspective: 'audits',
    dataSelection,
    host,
  });

  const isGrantedToSettings = useGranted([SETTINGS_SETACCESSES, SETTINGS_SECURITYACTIVITY, VIRTUAL_ORGANIZATION_ADMIN]);
  const isEnterpriseEdition = useEnterpriseEdition();

  const timeSeriesParameters = useMemo(() => {
    return resolvedDataSelection.map((selection) => {
      return {
        field:
          selection.date_attribute && selection.date_attribute.length > 0
            ? selection.date_attribute
            : 'timestamp',
        types: ['History', 'Activity'],
        filters: removeEntityTypeAllFromFilterGroup(selection.filters),
      };
    });
  }, [resolvedDataSelection]);

  const fallbackDates = useMemo(() => ({
    start: monthsAgo(12),
    end: now(),
  }), []);

  const queryRef = useQueryLoading<AuditsMultiVerticalBarsTimeSeriesQuery>(
    auditsMultiVerticalBarsTimeSeriesQuery,
    {
      operation: 'count',
      startDate: startDate ?? fallbackDates.start,
      endDate: endDate ?? fallbackDates.end,
      interval: parameters.interval ?? 'day',
      timeSeriesParameters,
    },
  );

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
        <AuditsMultiVerticalBarsComponent
          queryRef={queryRef}
          dataSelection={resolvedDataSelection}
          interval={parameters.interval}
          isStacked={parameters.stacked}
          hasLegend={parameters.legend}
          onMounted={setChart}
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
    >
      {renderContent()}
    </WidgetContainer>
  );
};

export default AuditsMultiVerticalBars;
