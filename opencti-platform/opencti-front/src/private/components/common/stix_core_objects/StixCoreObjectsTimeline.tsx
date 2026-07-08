import React, { ReactNode, Suspense } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { OrderingMode, StixCoreObjectsOrdering, StixCoreObjectsTimelineQuery } from './__generated__/StixCoreObjectsTimelineQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import { buildFiltersAndOptionsForWidgets, normalizeFilterGroupForBackend } from '../../../../utils/filters/filtersUtils';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetTimeline from '../../../../components/dashboard/WidgetTimeline';
import { resolveLink } from '../../../../utils/Entity';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import type { WidgetDataSelection, WidgetHost, WidgetParameters } from '../../../../utils/widget/widget';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import WidgetNoHostEntity from '../../../../components/dashboard/WidgetNoHostEntity';
import { DashboardConfig } from '../../../../components/dashboard/dashboard-types';
import { computeStartEndDates } from '../../../../components/dashboard/dashboardVizUtils';

const stixCoreObjectsTimelineQuery = graphql`
  query StixCoreObjectsTimelineQuery(
    $types: [String]
    $first: Int
    $orderBy: StixCoreObjectsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    stixCoreObjects(
      types: $types
      first: $first
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) {
      edges {
        node {
          id
          entity_type
          created_at
          updated_at
          ... on StixDomainObject  {
            modified
            created
          }
          ... on Event {
            start_time
            stop_time
          }
          createdBy {
            ... on Identity {
              id
              name
              entity_type
            }
          }
          objectMarking {
            id
            definition_type
            definition
            x_opencti_order
            x_opencti_color
          }
          representative {
            main
            secondary
          }
        }
      }
    }
  }
`;

interface StixCoreObjectsTimelineComponentProps {
  queryRef: PreloadedQuery<StixCoreObjectsTimelineQuery>;
  dataSelection: WidgetDataSelection[];
}

const StixCoreObjectsTimelineComponent = ({
  queryRef,
  dataSelection,
}: StixCoreObjectsTimelineComponentProps) => {
  const data = usePreloadedQuery(stixCoreObjectsTimelineQuery, queryRef);

  const edges = data?.stixCoreObjects?.edges ?? [];
  const selection = dataSelection[0];

  const dateAttribute
    = selection.date_attribute && selection.date_attribute.length > 0
      ? selection.date_attribute
      : 'created_at';

  return edges.length === 0 ? (
    <WidgetNoData />
  ) : (
    <WidgetTimeline
      data={edges.map((edge) => {
        const node = edge.node;
        return {
          value: node,
          link: `${resolveLink(node.entity_type)}/${node.id}`,
        };
      })}
      dateAttribute={dateAttribute}
    />
  );
};

interface StixCoreObjectsTimelineProps {
  variant?: string;
  height?: number;
  dataSelection: WidgetDataSelection[];
  parameters?: WidgetParameters;
  popover?: ReactNode;
  host?: WidgetHost;
  config: DashboardConfig;
  refreshRate?: number | null;
}

const DATA_SELECTION_TYPES = ['Stix-Core-Object'];

const buildQueryVariables = (
  resolvedDataSelection: WidgetDataSelection[],
  config: DashboardConfig,
) => {
  const selection = resolvedDataSelection[0];
  const dateAttribute
    = selection.date_attribute && selection.date_attribute.length > 0
      ? selection.date_attribute
      : 'created_at';
  const { startDate, endDate } = computeStartEndDates(config);
  const { filters } = buildFiltersAndOptionsForWidgets(
    selection.filters,
    { startDate, endDate, dateAttribute },
  );
  return {
    types: DATA_SELECTION_TYPES,
    first: selection.number ?? 10,
    orderBy: dateAttribute as StixCoreObjectsOrdering,
    orderMode: (selection.sort_mode ?? 'desc') as OrderingMode,
    filters: normalizeFilterGroupForBackend(filters),
  };
};

const StixCoreObjectsTimeline = ({
  variant,
  height,
  dataSelection,
  parameters = {},
  popover,
  host,
  config,
  refreshRate = null,
}: StixCoreObjectsTimelineProps) => {
  const { t_i18n } = useFormatter();
  const { resolvedDataSelection, isMissingHostEntity, isPreviewMode, queryRef } = useDashboardViz<StixCoreObjectsTimelineQuery>({
    perspective: 'entities',
    dataSelection,
    host,
    refreshRate,
    query: stixCoreObjectsTimelineQuery,
    config,
    buildQueryVariables,
  });
  const renderContent = () => {
    if (isMissingHostEntity) {
      return <WidgetNoHostEntity host={host} />;
    }

    if (!queryRef) return null;

    return (
      <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
        <StixCoreObjectsTimelineComponent
          queryRef={queryRef}
          dataSelection={resolvedDataSelection}
        />
      </Suspense>
    );
  };

  return (
    <WidgetContainer
      height={height}
      title={parameters.title ?? t_i18n('Entities list')}
      variant={variant}
      action={popover}
      showPreviewTag={isPreviewMode}
    >
      {renderContent()}
    </WidgetContainer>
  );
};

export default StixCoreObjectsTimeline;
