import { PreloadedQuery, usePreloadedQuery, VariablesOf } from 'react-relay';
import type { GraphQLTaggedNode, OperationType } from 'relay-runtime';
import React, { useState } from 'react';
import ApexCharts from 'apexcharts';
import type { PublicWidgetContainerProps } from './PublicWidgetContainerProps';
import { useFormatter } from '../../../components/i18n';
import usePublicDashboardViz from './usePublicDashboardViz';
import usePublicWidgetDefaultDates from './usePublicWidgetDefaultDates';
import WidgetContainer from '../../../components/dashboard/WidgetContainer';
import WidgetTimeSeriesBreakdown, { WidgetTimeSeriesBreakdownData } from '../../../components/dashboard/WidgetTimeSeriesBreakdown';
import Loader, { LoaderVariant } from '../../../components/Loader';
import type { Widget } from '../../../utils/widget/widget';
import { getWidgetInterval } from '../../../utils/widget/widgetUtils';
import { getBreakdownDefaultStartDate } from '../../../utils/widget/widgetBreakdown';

interface PublicTimeSeriesBreakdownQueryProps<TQuery extends OperationType> {
  // Takes the public dashboard, the widget and the dates: every breakdown setting is read from the stored widget
  query: GraphQLTaggedNode;
  selectBreakdown: (data: TQuery['response']) => WidgetTimeSeriesBreakdownData | null | undefined;
}

interface PublicTimeSeriesBreakdownContentProps<TQuery extends OperationType> extends PublicTimeSeriesBreakdownQueryProps<TQuery> {
  type: string;
  parameters: NonNullable<Widget['parameters']>;
  queryRef: PreloadedQuery<TQuery>;
  onMounted: (chart: ApexCharts) => void;
  onWarningChange: (warning?: string) => void;
}

const PublicTimeSeriesBreakdownContent = <TQuery extends OperationType>({
  query,
  selectBreakdown,
  type,
  parameters,
  queryRef,
  onMounted,
  onWarningChange,
}: PublicTimeSeriesBreakdownContentProps<TQuery>) => {
  const data = usePreloadedQuery<TQuery>(query, queryRef);
  return (
    <WidgetTimeSeriesBreakdown
      breakdown={selectBreakdown(data)}
      type={type}
      parameters={parameters}
      onMounted={onMounted}
      onWarningChange={onWarningChange}
    />
  );
};

/**
 * Time series widget of a public dashboard drawing one series per value of `parameters.breakdownBy`.
 */
const PublicTimeSeriesBreakdown = <TQuery extends OperationType>({
  uriKey,
  widget,
  startDate,
  endDate,
  title,
  query,
  selectBreakdown,
}: PublicWidgetContainerProps & PublicTimeSeriesBreakdownQueryProps<TQuery>) => {
  const { t_i18n } = useFormatter();
  const [chart, setChart] = useState<ApexCharts>();
  const [warning, setWarning] = useState<string>();
  const { id, type } = widget;
  const parameters = widget.parameters ?? {};
  // Same default as the dashboard widget: a daily breakdown only looks back a short while
  const dates = usePublicWidgetDefaultDates(
    startDate,
    endDate,
    () => getBreakdownDefaultStartDate(getWidgetInterval(parameters)),
  );
  const queryRef = usePublicDashboardViz<TQuery>(query, { uriKey, widgetId: id, ...dates } as VariablesOf<TQuery>);

  return (
    <WidgetContainer
      title={parameters.title ?? title ?? t_i18n('Entities history')}
      chart={chart}
      warning={warning}
    >
      {queryRef ? (
        <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <PublicTimeSeriesBreakdownContent<TQuery>
            query={query}
            selectBreakdown={selectBreakdown}
            queryRef={queryRef}
            type={type}
            parameters={parameters}
            onMounted={setChart}
            onWarningChange={setWarning}
          />
        </React.Suspense>
      ) : (
        <Loader variant={LoaderVariant.inElement} />
      )}
    </WidgetContainer>
  );
};

export default PublicTimeSeriesBreakdown;
