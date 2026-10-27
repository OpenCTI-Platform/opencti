import React, { ReactNode, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import ApexCharts from 'apexcharts';
import { useFormatter } from '../../../../components/i18n';
import useAuth from '../../../../utils/hooks/useAuth';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetTimeSeriesBreakdown from '../../../../components/dashboard/WidgetTimeSeriesBreakdown';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import WidgetRenderContent from '../../../../components/dashboard/WidgetRenderContent';
import { Widget, WidgetDataSelection, WidgetHost, WidgetParameters } from '../../../../utils/widget/widget';
import { DashboardConfig } from '../../../../components/dashboard/dashboard-types';
import { computeStartEndDates, computeWidgetFiltersForSelection } from '../../../../components/dashboard/dashboardVizUtils';
import { getWidgetInterval } from '../../../../utils/widget/widgetUtils';
import {
  getBreakdownDefaultStartDate,
  getBreakdownEntityTypes,
  getWidgetBreakdownLimit,
  getWidgetBreakdownOrder,
  getWidgetBreakdownOther,
  isBreakdownField,
  isBreakdownFieldSupported,
} from 'src/utils/widget/widgetBreakdown';
import { now } from '../../../../utils/Time';
import { StixCoreObjectsTimeSeriesBreakdownQuery } from '@components/common/stix_core_objects/__generated__/StixCoreObjectsTimeSeriesBreakdownQuery.graphql';

const stixCoreObjectsTimeSeriesBreakdownQuery = graphql`
  query StixCoreObjectsTimeSeriesBreakdownQuery(
    $field: String!
    $dateAttribute: String
    $startDate: DateTime!
    $endDate: DateTime
    $interval: String!
    $limit: Int
    $order: OrderingMode
    $includeOther: Boolean
    $types: [String]
    $filters: FilterGroup
  ) {
    stixCoreObjectsTimeSeriesBreakdown(
      field: $field
      dateAttribute: $dateAttribute
      startDate: $startDate
      endDate: $endDate
      interval: $interval
      limit: $limit
      order: $order
      includeOther: $includeOther
      types: $types
      filters: $filters
    ) {
      truncated
      dates
      series {
        label
        isOther
        entity {
          ... on BasicObject {
            id
            entity_type
          }
          ... on StixObject {
            representative {
              main
            }
          }
          # internal objects
          ... on Creator {
            id
            name
          }
        }
        values
      }
    }
  }
`;

const DATA_SELECTION_TYPES = ['Stix-Core-Object'];

const buildQueryVariables = (
  resolvedDataSelection: WidgetDataSelection[],
  config: DashboardConfig,
  parameters?: WidgetParameters,
): StixCoreObjectsTimeSeriesBreakdownQuery['variables'] => {
  const breakdownBy = parameters?.breakdownBy;
  if (!isBreakdownField(breakdownBy)) {
    throw Error('Missing breakdown field');
  }
  const [selection] = resolvedDataSelection;
  const interval = getWidgetInterval(parameters);
  // Dates set on the dashboard are kept as is. Without a start date, a daily breakdown only looks
  // back a short while: the default 12 months would draw too many bars.
  const configuredDates = computeStartEndDates(config);
  const { dateAttribute, startDate, endDate, filters } = computeWidgetFiltersForSelection(
    selection,
    {
      ...config,
      relativeDate: null,
      startDate: configuredDates.startDate ?? getBreakdownDefaultStartDate(interval),
      endDate: configuredDates.endDate ?? now(),
    },
  );
  // The API checks the field against these types: send the ones the filters restrict to
  const entityTypes = getBreakdownEntityTypes(selection?.filters);
  return {
    field: breakdownBy,
    dateAttribute,
    startDate,
    endDate,
    interval,
    limit: getWidgetBreakdownLimit(parameters),
    order: getWidgetBreakdownOrder(parameters),
    includeOther: getWidgetBreakdownOther(parameters),
    types: entityTypes.length > 0 ? entityTypes : DATA_SELECTION_TYPES,
    filters,
  };
};

interface StixCoreObjectsTimeSeriesBreakdownComponentProps {
  queryRef: PreloadedQuery<StixCoreObjectsTimeSeriesBreakdownQuery>;
  type: string;
  parameters: WidgetParameters;
  onMounted: (chart: ApexCharts) => void;
  onWarningChange: (warning?: string) => void;
}

const StixCoreObjectsTimeSeriesBreakdownComponent = ({
  queryRef,
  type,
  parameters,
  onMounted,
  onWarningChange,
}: StixCoreObjectsTimeSeriesBreakdownComponentProps) => {
  const { stixCoreObjectsTimeSeriesBreakdown } = usePreloadedQuery(
    stixCoreObjectsTimeSeriesBreakdownQuery,
    queryRef,
  );
  return (
    <WidgetTimeSeriesBreakdown
      breakdown={stixCoreObjectsTimeSeriesBreakdown}
      type={type}
      parameters={parameters}
      onMounted={onMounted}
      onWarningChange={onWarningChange}
    />
  );
};

interface StixCoreObjectsTimeSeriesBreakdownProps {
  widget: Widget;
  popover?: ReactNode;
  host?: WidgetHost;
  config: DashboardConfig;
  refreshRate?: number | null;
}

const StixCoreObjectsTimeSeriesBreakdownViz = ({
  widget,
  popover,
  host,
  config,
  refreshRate = null,
}: StixCoreObjectsTimeSeriesBreakdownProps) => {
  const { t_i18n } = useFormatter();
  const [chart, setChart] = useState<ApexCharts>();
  const [warning, setWarning] = useState<string>();
  const parameters = widget.parameters ?? {};
  const { renderGuards, isPreviewMode, queryRef } = useDashboardViz<StixCoreObjectsTimeSeriesBreakdownQuery>({
    perspective: 'entities',
    dataSelection: widget.dataSelection,
    host,
    refreshRate,
    query: stixCoreObjectsTimeSeriesBreakdownQuery,
    config,
    parameters,
    buildQueryVariables,
  });

  return (
    <WidgetContainer
      padding="small"
      title={parameters.title ?? t_i18n('Entities history')}
      chart={chart}
      action={popover}
      showPreviewTag={isPreviewMode}
      warning={warning}
    >
      <WidgetRenderContent
        {...renderGuards}
        queryRef={queryRef}
        host={host}
      >
        <StixCoreObjectsTimeSeriesBreakdownComponent
          queryRef={queryRef!}
          type={widget.type}
          parameters={parameters}
          onMounted={setChart}
          onWarningChange={setWarning}
        />
      </WidgetRenderContent>
    </WidgetContainer>
  );
};

/**
 * Entities time series widget drawing one series per value of `parameters.breakdownBy`.
 * A field the dataset does not support is not queried: the API would refuse it.
 */
const StixCoreObjectsTimeSeriesBreakdown = (props: StixCoreObjectsTimeSeriesBreakdownProps) => {
  const { t_i18n } = useFormatter();
  const { schema: { filterKeysSchema } } = useAuth();
  const { widget, popover } = props;
  if (!isBreakdownFieldSupported(filterKeysSchema, widget)) {
    return (
      <WidgetContainer padding="small" title={widget.parameters?.title ?? t_i18n('Entities history')} action={popover}>
        <WidgetNoData message={t_i18n('This breakdown field is not available for the dataset of this widget. Edit the widget to choose another field.')} />
      </WidgetContainer>
    );
  }
  return <StixCoreObjectsTimeSeriesBreakdownViz {...props} />;
};

export default StixCoreObjectsTimeSeriesBreakdown;
