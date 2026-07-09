import React, { ReactNode } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import useGranted, { SETTINGS_SETACCESSES } from '../../../../utils/hooks/useGranted';
import { buildFiltersAndOptionsForWidgets, normalizeFilterGroupForBackend } from '../../../../utils/filters/filtersUtils';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetDistributionList from '../../../../components/dashboard/WidgetDistributionList';
import { getMainRepresentative, isFieldForIdentifier } from '../../../../utils/defaultRepresentatives';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import WidgetRenderContent from '../../../../components/dashboard/WidgetRenderContent';
import type { Widget, WidgetDataSelection, WidgetHost } from '../../../../utils/widget/widget';
import { StixCoreObjectsDistributionListDistributionQuery } from './__generated__/StixCoreObjectsDistributionListDistributionQuery.graphql';
import type { DashboardConfig } from '../../../../components/dashboard/dashboard-types';
import { computeStartEndDates } from '../../../../components/dashboard/dashboardVizUtils';

const stixCoreObjectsDistributionListDistributionQuery = graphql`
  query StixCoreObjectsDistributionListDistributionQuery(
    $objectId: [String]
    $relationship_type: [String]
    $toTypes: [String]
    $field: String!
    $startDate: DateTime
    $endDate: DateTime
    $dateAttribute: String
    $operation: StatsOperation!
    $limit: Int
    $order: String
    $types: [String]
    $filters: FilterGroup
    $search: String
  ) {
    stixCoreObjectsDistribution(
      objectId: $objectId
      relationship_type: $relationship_type
      toTypes: $toTypes
      field: $field
      startDate: $startDate
      endDate: $endDate
      dateAttribute: $dateAttribute
      operation: $operation
      limit: $limit
      order: $order
      types: $types
      filters: $filters
      search: $search
    ) {
      label
      value
      entity {
        ... on BasicObject {
          id
          entity_type
        }
        ... on BasicRelationship {
          id
          entity_type
        }
        ... on StixObject {
          representative {
            main
          }
        }
        # use colors when available
        ... on Label {
          color
        }
        ... on MarkingDefinition {
          x_opencti_color
        }
        # objects without representative
        ... on Creator {
          name
        }
        ... on Group {
          name
        }
        ... on Status {
          template {
            name
            color
          }
        }
      }
    }
  }
`;

interface StixCoreObjectsDistributionListComponentProps {
  queryRef: PreloadedQuery<StixCoreObjectsDistributionListDistributionQuery>;
  dataSelection: Widget['dataSelection'];
  hasSetAccess: boolean;
}

const StixCoreObjectsDistributionListComponent = ({
  queryRef,
  dataSelection,
  hasSetAccess,
}: StixCoreObjectsDistributionListComponentProps) => {
  const data = usePreloadedQuery(stixCoreObjectsDistributionListDistributionQuery, queryRef);
  const selection = dataSelection[0];
  const raw = data?.stixCoreObjectsDistribution ?? [];
  if (raw.length === 0) {
    return <WidgetNoData />;
  }
  const formatted = raw.map((n) => {
    let label = n?.label;
    if (isFieldForIdentifier(selection.attribute ?? undefined)) {
      label = getMainRepresentative(n?.entity);
    } else if (
      selection.attribute === 'entity_type'
      && n?.label
    ) {
      const translated = `entity_${n.label}`;
      label = translated !== n.label ? translated : n.label;
    }

    return {
      label,
      value: n?.value,
      color: n?.entity?.color ?? n?.entity?.x_opencti_color,
      id: selection.attribute?.endsWith('_id') ? n?.entity?.id : null,
      type: n?.entity?.entity_type ?? n?.label,
    };
  });

  return (
    <WidgetDistributionList
      data={formatted}
      hasSettingAccess={hasSetAccess}
    />
  );
};

interface StixCoreObjectsDistributionListProps {
  dataSelection: Widget['dataSelection'];
  parameters: { title?: string };
  popover?: ReactNode;
  variant?: string;
  height?: number;
  host?: WidgetHost;
  config: DashboardConfig;
  refreshRate?: number | null;
}

const DATA_SELECTION_TYPES = ['Stix-Core-Object'];

const buildQueryVariables = (resolvedDataSelection: WidgetDataSelection[], config: DashboardConfig) => {
  const selection = resolvedDataSelection[0];
  const dateAttribute = selection.date_attribute && selection.date_attribute.length > 0
    ? selection.date_attribute
    : 'created_at';
  const { startDate, endDate } = computeStartEndDates(config);
  const { filters } = buildFiltersAndOptionsForWidgets(
    selection.filters,
    { startDate, endDate, dateAttribute },
  );
  return {
    types: DATA_SELECTION_TYPES,
    field: selection.attribute ?? 'entity_type',
    operation: 'count' as StixCoreObjectsDistributionListDistributionQuery['variables']['operation'],
    startDate: config?.startDate,
    endDate: config?.endDate,
    dateAttribute,
    filters: normalizeFilterGroupForBackend(filters),
    limit: selection.number ?? 10,
  };
};

const StixCoreObjectsDistributionList = ({
  variant,
  height,
  dataSelection,
  parameters = {},
  popover,
  config,
  refreshRate = null,
  host,
}: StixCoreObjectsDistributionListProps) => {
  const { t_i18n } = useFormatter();
  const hasSetAccess = useGranted([SETTINGS_SETACCESSES]);
  const { resolvedDataSelection, isMissingHostEntity, isMissingSavedFilters, isPreviewMode, queryRef } = useDashboardViz<StixCoreObjectsDistributionListDistributionQuery>({
    perspective: 'entities',
    dataSelection,
    host,
    refreshRate,
    query: stixCoreObjectsDistributionListDistributionQuery,
    config,
    buildQueryVariables,
  });

  return (
    <WidgetContainer
      height={height}
      title={parameters.title ?? t_i18n('Distribution of entities')}
      variant={variant}
      action={popover}
      showPreviewTag={isPreviewMode}
    >
      <div style={{ height: '100%' }}>
        <WidgetRenderContent
          isMissingHostEntity={isMissingHostEntity}
          isMissingSavedFilters={isMissingSavedFilters}
          queryRef={queryRef}
          host={host}
        >
          <StixCoreObjectsDistributionListComponent
            queryRef={queryRef!}
            dataSelection={resolvedDataSelection}
            hasSetAccess={hasSetAccess}
          />
        </WidgetRenderContent>
      </div>
    </WidgetContainer>
  );
};

export default StixCoreObjectsDistributionList;
