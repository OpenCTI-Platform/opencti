import React, { CSSProperties, ReactNode, useCallback, useMemo, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import ApexCharts from 'apexcharts';
import { Box, Stack, Typography } from '@mui/material';
import { useFormatter } from '../../../../components/i18n';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetDonut from '../../../../components/dashboard/WidgetDonut';
import WidgetHorizontalBars from '../../../../components/dashboard/WidgetHorizontalBars';
import WidgetDistributionList from '../../../../components/dashboard/WidgetDistributionList';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import type { DashboardConfig } from '../../../../components/dashboard/dashboard-types';
import type { WidgetDataSelection, WidgetHost, WidgetParameters } from '../../../../utils/widget/widget';
import { normalizeFilterGroupForBackend } from '../../../../utils/filters/filtersUtils';
import useDistributionGraphData from '../../../../utils/hooks/useDistributionGraphData';
import { findSourceWidgetMetric, toWidgetValue } from '../../integrations/sources/sourceIntelligenceUtils';
import SourcesWidgetRenderContent from './SourcesWidgetRenderContent';
import { metricAxisTitle, NO_SOURCE_SCORED_MESSAGE, periodDaysFromDashboardConfig, periodFromDashboardConfig } from './sourcesWidgetUtils';
import { SourcesDistributionQuery } from './__generated__/SourcesDistributionQuery.graphql';

const sourcesDistributionQuery = graphql`
  query SourcesDistributionQuery(
    $metric: String!
    $period: SourceScorecardPeriod
    $filters: FilterGroup
    $first: Int
    $orderMode: OrderingMode
  ) {
    sourceScorecardsDistribution(metric: $metric, period: $period, filters: $filters, first: $first, orderMode: $orderMode) {
      label
      value
      currency
      entity {
        id
        entity_type
        name
      }
    }
  }
`;

export type SourcesDistributionVariant = 'list' | 'distribution-list' | 'horizontal-bar' | 'donut';

const DEFAULT_ITEMS = 10;

const SourcesDistributionComponent = ({ queryRef, selection, widgetType, onMounted }: {
  queryRef: PreloadedQuery<SourcesDistributionQuery>;
  selection: WidgetDataSelection;
  widgetType: SourcesDistributionVariant;
  onMounted: (chart: ApexCharts) => void;
}) => {
  const { t_i18n } = useFormatter();
  const { buildWidgetProps } = useDistributionGraphData();
  const { sourceScorecardsDistribution } = usePreloadedQuery(sourcesDistributionQuery, queryRef);
  const metric = findSourceWidgetMetric(selection.attribute, widgetType);
  const data = useMemo(() => sourceScorecardsDistribution
    .map((item) => ({
      label: item.label,
      value: toWidgetValue(item.value, metric.type),
      id: item.entity?.id,
      type: 'Source',
      entity: item.entity ? { id: item.entity.id, entity_type: item.entity.entity_type, name: item.entity.name } : null,
    }))
    .filter((item) => item.value !== null), [sourceScorecardsDistribution, metric]);

  if (data.length === 0) {
    return <WidgetNoData message={t_i18n(NO_SOURCE_SCORED_MESSAGE)} />;
  }
  const currency = metric.type === 'cost' ? (sourceScorecardsDistribution.find((item) => item.currency)?.currency ?? null) : null;
  // Cost values are in the currency the widget aggregated
  const withCurrency = (content: React.ReactNode) => (currency ? (
    <Stack sx={{ height: '100%' }}>
      <Typography variant="caption" sx={{ color: 'text.secondary' }}>{t_i18n('Values in {currency}', { values: { currency } })}</Typography>
      <Box sx={{ flex: 1, minHeight: 0 }}>{content}</Box>
    </Stack>
  ) : content);
  if (widgetType === 'donut') {
    return withCurrency(<WidgetDonut data={data} groupBy="name" onMounted={onMounted} />);
  }
  if (widgetType === 'horizontal-bar') {
    const { series, redirectionUtils } = buildWidgetProps(data, selection, metricAxisTitle(t_i18n, metric, currency));
    return withCurrency(
      <WidgetHorizontalBars
        series={series}
        distributed={false}
        redirectionUtils={redirectionUtils}
        onMounted={onMounted}
      />,
    );
  }
  return withCurrency(<WidgetDistributionList data={data} hasSettingAccess />);
};

interface SourcesDistributionProps {
  widgetType: SourcesDistributionVariant;
  variant?: string;
  height?: CSSProperties['height'];
  dataSelection: WidgetDataSelection[];
  parameters?: WidgetParameters;
  popover?: ReactNode;
  host?: WidgetHost;
  config: DashboardConfig;
  refreshRate?: number | null;
}

const SourcesDistribution = ({ widgetType, variant, height, dataSelection, parameters = {}, popover, host, config, refreshRate = null }: SourcesDistributionProps) => {
  const { t_i18n } = useFormatter();
  const [chart, setChart] = useState<ApexCharts>();
  const buildQueryVariables = useCallback((resolved: WidgetDataSelection[], dashboardConfig: DashboardConfig): SourcesDistributionQuery['variables'] => {
    const selection = resolved[0];
    return {
      metric: findSourceWidgetMetric(selection.attribute, widgetType).key,
      period: periodFromDashboardConfig(dashboardConfig),
      filters: normalizeFilterGroupForBackend(selection.filters),
      first: selection.number ?? DEFAULT_ITEMS,
      orderMode: selection.sort_mode === 'asc' ? 'asc' : 'desc',
    };
  }, [widgetType]);
  const { resolvedDataSelection, isMissingHostEntity, isMissingSavedFilters, isPreviewMode, queryRef } = useDashboardViz<SourcesDistributionQuery>({
    perspective: 'sources',
    dataSelection,
    host,
    refreshRate,
    query: sourcesDistributionQuery,
    config,
    parameters,
    buildQueryVariables,
  });
  const selection = resolvedDataSelection[0] ?? dataSelection[0];
  const metric = findSourceWidgetMetric(selection?.attribute, widgetType);
  return (
    <WidgetContainer
      padding="small"
      height={height}
      title={parameters.title || t_i18n('{measure} over the last {days} days', { values: { measure: t_i18n(metric.label), days: periodDaysFromDashboardConfig(config) } })}
      variant={variant}
      chart={chart}
      action={popover}
      showPreviewTag={isPreviewMode}
    >
      <SourcesWidgetRenderContent isMissingHostEntity={isMissingHostEntity} isMissingSavedFilters={isMissingSavedFilters} queryRef={queryRef} host={host}>
        <SourcesDistributionComponent queryRef={queryRef!} selection={selection} widgetType={widgetType} onMounted={setChart} />
      </SourcesWidgetRenderContent>
    </WidgetContainer>
  );
};

export default SourcesDistribution;
