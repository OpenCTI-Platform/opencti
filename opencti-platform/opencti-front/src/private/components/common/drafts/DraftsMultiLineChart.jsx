import React, { useState, useMemo, useEffect, useRef } from 'react';
import { graphql } from 'react-relay';
import { QueryRenderer } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import { buildFiltersAndOptionsForWidgets } from '../../../../utils/filters/filtersUtils';
import { computeStartEndDates } from '../../../../components/dashboard/dashboard-viz-utils';
import { useDashboardRefreshToken } from '../../../../components/dashboard/DashboardRefreshContext';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetMultiLines from '../../../../components/dashboard/WidgetMultiLines';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import WidgetNoHostEntity from '../../../../components/dashboard/WidgetNoHostEntity';

const draftsMultiLineChartTimeSeriesQuery = graphql`
  query DraftsMultiLineChartTimeSeriesQuery(
    $field: String!
    $operation: StatsOperation!
    $startDate: DateTime!
    $endDate: DateTime!
    $interval: String!
    $filters: FilterGroup
    $search: String
  ) {
    draftWorkspacesTimeSeries(
      field: $field
      operation: $operation
      startDate: $startDate
      endDate: $endDate
      interval: $interval
      filters: $filters
      search: $search
    ) {
      date
      value
    }
  }
`;

const DraftsMultiLineChart = ({
  variant,
  height,
  config,
  refreshRate = null,
  dataSelection,
  parameters = {},
  popover,
  host,
}) => {
  const { t_i18n } = useFormatter();
  const [chart, setChart] = useState();
  const { resolvedDataSelection, isMissingHostEntity, isPreviewMode } = useDashboardViz({
    perspective: 'entities',
    dataSelection,
    host,
  });

  const { startDate, endDate } = computeStartEndDates(config);

  const refreshToken = useDashboardRefreshToken();
  const [localRefreshKey, setLocalRefreshKey] = useState(0);
  const prevRefreshTokenRef = useRef(refreshToken);
  useEffect(() => {
    if (prevRefreshTokenRef.current === refreshToken) return;
    prevRefreshTokenRef.current = refreshToken;
    setLocalRefreshKey((k) => k + 1);
  }, [refreshToken]);
  useEffect(() => {
    if (!refreshRate || refreshToken !== null) return () => {};
    const interval = setInterval(() => setLocalRefreshKey((k) => k + 1), refreshRate);
    return () => clearInterval(interval);
  }, [refreshRate, refreshToken]);

  const selection = resolvedDataSelection[0];
  const { filters } = useMemo(() => buildFiltersAndOptionsForWidgets(selection?.filters), [selection]);

  const variables = useMemo(() => ({
    field: selection?.date_attribute && selection.date_attribute.length > 0
      ? selection.date_attribute
      : 'created_at',
    operation: 'count',
    startDate,
    endDate,
    interval: parameters.interval ?? 'day',
    filters,
  }), [startDate, endDate, parameters.interval, selection, filters]);

  const renderContent = () => {
    if (isMissingHostEntity) {
      return <WidgetNoHostEntity host={host} />;
    }
    return (
      <QueryRenderer
        key={localRefreshKey}
        query={draftsMultiLineChartTimeSeriesQuery}
        variables={variables}
        render={({ props }) => {
          if (props && props.draftWorkspacesTimeSeries) {
            return (
              <WidgetMultiLines
                series={[{
                  name: selection?.label || t_i18n('Number of draft workspaces'),
                  data: props.draftWorkspacesTimeSeries.map((entry) => ({
                    x: new Date(entry.date),
                    y: entry.value,
                  })),
                }]}
                interval={parameters.interval}
                hasLegend={parameters.legend}
                onMounted={setChart}
              />
            );
          }
          if (props) {
            return <WidgetNoData />;
          }
          return <Loader variant={LoaderVariant.inElement} />;
        }}
      />
    );
  };

  return (
    <WidgetContainer
      padding="small"
      height={height}
      title={parameters.title ?? t_i18n('Draft workspaces history')}
      variant={variant}
      chart={chart}
      action={popover}
      showPreviewTag={isPreviewMode}
    >
      {renderContent()}
    </WidgetContainer>
  );
};

export default DraftsMultiLineChart;
