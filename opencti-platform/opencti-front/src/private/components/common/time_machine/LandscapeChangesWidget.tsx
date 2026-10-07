import React, { ReactNode } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { Link } from 'react-router';
import { Text } from '@filigran/design-system';
import { Box, List, ListItem, ListItemText } from '@mui/material';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetDistributionList from '../../../../components/dashboard/WidgetDistributionList';
import WidgetRenderContent from '../../../../components/dashboard/WidgetRenderContent';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import { computeStartEndDates } from '../../../../components/dashboard/dashboardVizUtils';
import type { DashboardConfig } from '../../../../components/dashboard/dashboard-types';
import { useFormatter } from '../../../../components/i18n';
import { normalizeFilterGroupForBackend } from '../../../../utils/filters/filtersUtils';
import { resolveLink } from '../../../../utils/Entity';
import type { Widget, WidgetDataSelection, WidgetHost } from '../../../../utils/widget/widget';
import { countLabel, entityChangesPath, widgetDefaultRange } from './timeMachineUtils';
import { LandscapeChangesWidgetQuery } from './__generated__/LandscapeChangesWidgetQuery.graphql';

const landscapeChangesWidgetQuery = graphql`
  query LandscapeChangesWidgetQuery($input: LandscapeDiffInput!) {
    landscapeDiffSummary(input: $input) {
      from
      to
      truncated
      aggregates {
        new_relationships_by_type { key label count }
        new_techniques_by_tactic { key label count }
      }
      entities {
        entity_id
        entity_type
        name
        change_score
        relationships_added
        attributes_changed
      }
    }
  }
`;

export type LandscapeChangesWidgetVariant = 'landscape-relationships' | 'landscape-techniques' | 'landscape-top-entities';

const TOP_ENTITIES_LIMIT = 10;

/**
 * Landscape diff of the widget filter set since the start date of the dashboard
 * (30 days when the dashboard has no start date) up to its end date (or now).
 */
export const buildLandscapeWidgetVariables = (resolvedDataSelection: WidgetDataSelection[], config: DashboardConfig) => {
  const selection = resolvedDataSelection[0];
  const { startDate, endDate } = computeStartEndDates(config);
  const fallback = widgetDefaultRange();
  const filters = selection?.filters ? normalizeFilterGroupForBackend(selection.filters) : null;
  return {
    input: {
      filters: filters ? JSON.stringify(filters) : null,
      entity_types: ['Stix-Domain-Object'],
      from: startDate ?? fallback.from,
      to: endDate ?? fallback.to,
    },
  };
};

// The scope exceeded the limits of a widget summary: the figures only cover its most recent part
const PartialNotice = ({ truncated }: { truncated: boolean }) => {
  const { t_i18n } = useFormatter();
  if (!truncated) return null;
  return (
    <Text variant="content-caption" as="p" style={{ color: 'var(--text-default-secondary)', marginBottom: 4 }} data-testid="landscape-widget-partial">
      {t_i18n('Partial result: the scope exceeds the limits of a widget, only its most recent entities and relationships are compared.')}
    </Text>
  );
};

const LandscapeChangesWidgetComponent = ({
  queryRef,
  variant,
}: {
  queryRef: PreloadedQuery<LandscapeChangesWidgetQuery>;
  variant: LandscapeChangesWidgetVariant;
}) => {
  const { t_i18n, n } = useFormatter();
  const data = usePreloadedQuery(landscapeChangesWidgetQuery, queryRef);
  const summary = data.landscapeDiffSummary;
  if (!summary) return <WidgetNoData />;
  if (variant === 'landscape-top-entities') {
    const entities = summary.entities.slice(0, TOP_ENTITIES_LIMIT);
    if (entities.length === 0) return <WidgetNoData />;
    const period = { from: summary.from, to: summary.to };
    return (
      <Box sx={{ height: '100%', overflow: 'auto' }}>
        <PartialNotice truncated={summary.truncated} />
        <List dense sx={{ width: '100%' }} data-testid="landscape-widget-top-entities">
          {entities.map((entity) => {
            const base = resolveLink(entity.entity_type);
            return (
              <ListItem key={entity.entity_id} divider secondaryAction={<Text variant="content-compact">{n(entity.change_score)}</Text>}>
                <ListItemText
                  primary={base ? <Link to={entityChangesPath(base, entity.entity_id, entity.entity_type, period)}>{entity.name}</Link> : entity.name}
                  secondary={t_i18n('{type} - {relationships}, {attributes}', { values: { type: t_i18n(`entity_${entity.entity_type}`), relationships: countLabel('new_relationships', entity.relationships_added, t_i18n), attributes: countLabel('attributes_changed', entity.attributes_changed, t_i18n) } })}
                />
              </ListItem>
            );
          })}
        </List>
      </Box>
    );
  }
  const buckets = variant === 'landscape-techniques'
    ? summary.aggregates.new_techniques_by_tactic
    : summary.aggregates.new_relationships_by_type;
  if (buckets.length === 0) return <WidgetNoData />;
  const entries = buckets.map((bucket) => ({
    label: variant === 'landscape-relationships' ? t_i18n(`relationship_${bucket.label}`) : bucket.label,
    value: bucket.count,
  }));
  return (
    <Box sx={{ height: '100%', overflow: 'auto' }} data-testid={`landscape-widget-${variant}`}>
      <PartialNotice truncated={summary.truncated} />
      <WidgetDistributionList data={entries} />
    </Box>
  );
};

interface LandscapeChangesWidgetProps {
  variant: LandscapeChangesWidgetVariant;
  dataSelection: Widget['dataSelection'];
  parameters?: { title?: string | null } | null;
  popover?: ReactNode;
  host?: WidgetHost;
  config: DashboardConfig;
  refreshRate?: number | null;
}

const LandscapeChangesWidget = ({ variant, dataSelection, parameters, popover, host, config, refreshRate = null }: LandscapeChangesWidgetProps) => {
  const { t_i18n } = useFormatter();
  const defaultTitles: Record<LandscapeChangesWidgetVariant, string> = {
    'landscape-relationships': t_i18n('New relationships by type'),
    'landscape-techniques': t_i18n('New techniques by tactic'),
    'landscape-top-entities': t_i18n('Top changed entities'),
  };
  const { isMissingHostEntity, isMissingSavedFilters, isPreviewMode, queryRef } = useDashboardViz<LandscapeChangesWidgetQuery>({
    perspective: 'entities',
    dataSelection,
    host,
    refreshRate,
    query: landscapeChangesWidgetQuery,
    buildQueryVariables: buildLandscapeWidgetVariables,
    config,
  });
  return (
    <WidgetContainer
      padding="medium"
      title={parameters?.title || defaultTitles[variant]}
      action={popover}
      showPreviewTag={isPreviewMode}
    >
      <WidgetRenderContent
        isMissingHostEntity={isMissingHostEntity}
        isMissingSavedFilters={isMissingSavedFilters}
        queryRef={queryRef}
        host={host}
      >
        <LandscapeChangesWidgetComponent queryRef={queryRef!} variant={variant} />
      </WidgetRenderContent>
    </WidgetContainer>
  );
};

export default LandscapeChangesWidget;
