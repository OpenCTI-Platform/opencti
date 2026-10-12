import React, { CSSProperties, ReactNode, useCallback } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNumber from '../../../../components/dashboard/WidgetNumber';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import type { DashboardConfig } from '../../../../components/dashboard/dashboard-types';
import type { WidgetDataSelection, WidgetHost, WidgetParameters } from '../../../../utils/widget/widget';
import { normalizeFilterGroupForBackend } from '../../../../utils/filters/filtersUtils';
import { findSourceWidgetMetric, toWidgetValue } from '../../integrations/sources/sourceIntelligenceUtils';
import SourcesWidgetRenderContent from './SourcesWidgetRenderContent';
import {
  metricAxisTitle,
  NO_SOURCE_SCORED_MESSAGE,
  numberWidgetMetricKey,
  periodDaysFromDashboardConfig,
  periodFromDashboardConfig,
  SOURCES_NUMBER_COUNT_MODE as COUNT_MODE,
  type SourcesAggregation,
  toAggregation,
} from './sourcesWidgetUtils';
import { SourcesNumberQuery } from './__generated__/SourcesNumberQuery.graphql';

const sourcesNumberQuery = graphql`
  query SourcesNumberQuery(
    $metric: String!
    $period: SourceScorecardPeriod
    $filters: FilterGroup
    $aggregation: SourceScorecardAggregation
  ) {
    sourceScorecardsNumber(metric: $metric, period: $period, filters: $filters, aggregation: $aggregation) {
      value
      sources_count
      currency
    }
  }
`;

const NUMBER_TITLES: Record<SourcesAggregation, string> = {
  avg: '{measure}, average over the last {days} days',
  sum: '{measure}, total over the last {days} days',
  min: '{measure}, lowest over the last {days} days',
  max: '{measure}, highest over the last {days} days',
};

const SourcesNumberComponent = ({ queryRef, selection, label }: {
  queryRef: PreloadedQuery<SourcesNumberQuery>;
  selection: WidgetDataSelection;
  label: string;
}) => {
  const { t_i18n } = useFormatter();
  const { sourceScorecardsNumber } = usePreloadedQuery(sourcesNumberQuery, queryRef);
  const metric = findSourceWidgetMetric(selection.attribute);
  const value = selection.sort_mode === COUNT_MODE
    ? sourceScorecardsNumber.sources_count
    : toWidgetValue(sourceScorecardsNumber.value, metric.type);
  if (value === null || value === undefined || sourceScorecardsNumber.sources_count === 0) {
    return <WidgetNoData message={t_i18n(NO_SOURCE_SCORED_MESSAGE)} />;
  }
  const currency = selection.sort_mode !== COUNT_MODE && metric.type === 'cost' ? sourceScorecardsNumber.currency : null;
  return <WidgetNumber label={currency ? t_i18n('{measure} ({currency})', { values: { measure: label, currency } }) : label} value={value} />;
};

interface SourcesNumberProps {
  variant?: string;
  height?: CSSProperties['height'];
  dataSelection: WidgetDataSelection[];
  parameters?: WidgetParameters;
  popover?: ReactNode;
  host?: WidgetHost;
  config: DashboardConfig;
  refreshRate?: number | null;
}

const SourcesNumber = ({ variant, height, dataSelection, parameters = {}, popover, host, config, refreshRate = null }: SourcesNumberProps) => {
  const { t_i18n } = useFormatter();
  const buildQueryVariables = useCallback((resolved: WidgetDataSelection[], dashboardConfig: DashboardConfig): SourcesNumberQuery['variables'] => {
    const selection = resolved[0];
    return {
      metric: numberWidgetMetricKey(selection),
      period: periodFromDashboardConfig(dashboardConfig),
      filters: normalizeFilterGroupForBackend(selection.filters),
      aggregation: selection.sort_mode === COUNT_MODE ? 'sum' : toAggregation(selection.sort_mode, 'avg'),
    };
  }, []);
  const { resolvedDataSelection, isMissingHostEntity, isMissingSavedFilters, isPreviewMode, queryRef } = useDashboardViz<SourcesNumberQuery>({
    perspective: 'sources',
    dataSelection,
    host,
    refreshRate,
    query: sourcesNumberQuery,
    config,
    parameters,
    buildQueryVariables,
  });
  const selection = resolvedDataSelection[0] ?? dataSelection[0];
  const metric = findSourceWidgetMetric(selection?.attribute);
  const days = periodDaysFromDashboardConfig(config);
  const measure = metricAxisTitle(t_i18n, metric);
  const title = parameters.title || (selection?.sort_mode === COUNT_MODE
    ? t_i18n('Sources scored over the last {days} days', { values: { days } })
    : t_i18n(NUMBER_TITLES[toAggregation(selection?.sort_mode, 'avg')], { values: { measure, days } }));
  return (
    <WidgetContainer padding="medium" height={height} title={title} variant={variant} action={popover} showPreviewTag={isPreviewMode}>
      <SourcesWidgetRenderContent isMissingHostEntity={isMissingHostEntity} isMissingSavedFilters={isMissingSavedFilters} queryRef={queryRef} host={host}>
        <SourcesNumberComponent queryRef={queryRef!} selection={selection} label={title} />
      </SourcesWidgetRenderContent>
    </WidgetContainer>
  );
};

export default SourcesNumber;
