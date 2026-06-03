import React, { CSSProperties, ReactNode, Suspense, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import { buildFiltersAndOptionsForWidgets } from '../../../../utils/filters/filtersUtils';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetTree from '../../../../components/dashboard/WidgetTree';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import WidgetNoHostEntity from '../../../../components/dashboard/WidgetNoHostEntity';
import { StixRelationshipsTreeMapDistributionQuery } from './__generated__/StixRelationshipsTreeMapDistributionQuery.graphql';
import { WidgetDataSelection, WidgetHost, WidgetParameters } from '../../../../utils/widget/widget';
import { OpenCTIChartProps } from '@components/common/charts/Chart';
import { DashboardConfig } from '../../../../components/dashboard/dashboard-types';
import { StixRelationshipsMultiHeatMapTimeSeriesQuery } from '@components/common/stix_relationships/__generated__/StixRelationshipsMultiHeatMapTimeSeriesQuery.graphql';

const stixRelationshipsTreeMapsDistributionQuery = graphql`
  query StixRelationshipsTreeMapDistributionQuery(
    $field: String!
    $operation: StatsOperation!
    $startDate: DateTime
    $endDate: DateTime
    $dateAttribute: String
    $isTo: Boolean
    $limit: Int
    $fromOrToId: [String]
    $elementWithTargetTypes: [String]
    $fromId: [String]
    $fromRole: String
    $fromTypes: [String]
    $toId: [String]
    $toRole: String
    $toTypes: [String]
    $relationship_type: [String]
    $confidences: [Int]
    $search: String
    $filters: FilterGroup
    $dynamicFrom: FilterGroup
    $dynamicTo: FilterGroup
  ) {
    stixRelationshipsDistribution(
      field: $field
      operation: $operation
      startDate: $startDate
      endDate: $endDate
      dateAttribute: $dateAttribute
      isTo: $isTo
      limit: $limit
      fromOrToId: $fromOrToId
      elementWithTargetTypes: $elementWithTargetTypes
      fromId: $fromId
      fromRole: $fromRole
      fromTypes: $fromTypes
      toId: $toId
      toRole: $toRole
      toTypes: $toTypes
      relationship_type: $relationship_type
      confidences: $confidences
      search: $search
      filters: $filters
      dynamicFrom: $dynamicFrom
      dynamicTo: $dynamicTo
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
        # objects without representative
        ... on Creator {
          name
        }
        ... on Status {
          template {
            name
          }
        }
      }
    }
  }
`;

interface StixRelationshipsTreeMapComponentProps {
  queryRef: PreloadedQuery<StixRelationshipsTreeMapDistributionQuery>;
  dataSelection: WidgetDataSelection[];
  parameters?: WidgetParameters;
  onMounted?: OpenCTIChartProps['onMounted'];
}

const StixRelationshipsTreeMapComponent = ({
  queryRef,
  dataSelection,
  parameters,
  onMounted,
}: StixRelationshipsTreeMapComponentProps) => {
  const data = usePreloadedQuery(
    stixRelationshipsTreeMapsDistributionQuery,
    queryRef,
  );

  const distribution = data?.stixRelationshipsDistribution ?? [];
  const selection = dataSelection[0];

  if (!distribution.length) {
    return <WidgetNoData />;
  }

  return (
    <WidgetTree
      data={distribution}
      groupBy={selection.attribute ?? 'entity_type'}
      isDistributed={parameters?.distributed ?? undefined}
      onMounted={onMounted}
    />
  );
};

const buildQueryVariables = (
  resolvedDataSelection: WidgetDataSelection[],
  config: DashboardConfig,
): StixRelationshipsTreeMapDistributionQuery['variables'] => {
  const selection = resolvedDataSelection[0];
  const { startDate, endDate } = config;
  const dateAttribute
    = selection.date_attribute?.length
      ? selection.date_attribute
      : 'created_at';
  const { filters } = buildFiltersAndOptionsForWidgets(
    selection.filters,
    { isKnowledgeRelationshipWidget: true },
  );

  type QueryFilterGroup = NonNullable<NonNullable<StixRelationshipsMultiHeatMapTimeSeriesQuery['variables']['timeSeriesParameters']>[number]>['dynamicFrom'];

  return {
    field: selection.attribute ?? 'entity_type',
    operation: 'count',
    startDate,
    endDate,
    dateAttribute,
    limit: selection.number ?? 10,
    filters,
    isTo: selection.isTo,
    dynamicFrom: selection.dynamicFrom as unknown as QueryFilterGroup,
    dynamicTo: selection.dynamicTo as unknown as QueryFilterGroup,
  };
};

interface StixRelationshipsTreeMapProps {
  dataSelection: WidgetDataSelection[];
  parameters?: WidgetParameters;
  variant?: string;
  height?: CSSProperties['height'];
  popover?: ReactNode;
  host?: WidgetHost;
  config: DashboardConfig;
  refreshRate?: number | null;
}

const StixRelationshipsTreeMap = ({
  variant,
  height,
  dataSelection,
  parameters = {},
  popover,
  host,
  config,
  refreshRate = null,
}: StixRelationshipsTreeMapProps) => {
  const { t_i18n } = useFormatter();
  const [chart, setChart] = useState<ApexCharts>();
  const { resolvedDataSelection, isMissingHostEntity, isPreviewMode, queryRef } = useDashboardViz<StixRelationshipsTreeMapDistributionQuery>({
    perspective: 'relationships',
    dataSelection,
    host,
    refreshRate,
    query: stixRelationshipsTreeMapsDistributionQuery,
    config,
    buildQueryVariables,
  });

  if (isMissingHostEntity) {
    return <WidgetNoHostEntity host={host} />;
  }

  return (
    <WidgetContainer
      height={height}
      title={parameters?.title ?? t_i18n('Relationships distribution')}
      variant={variant}
      chart={chart}
      action={popover}
      showPreviewTag={isPreviewMode}
    >
      {queryRef ? (
        <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <StixRelationshipsTreeMapComponent
            queryRef={queryRef}
            dataSelection={resolvedDataSelection}
            parameters={parameters}
            onMounted={setChart}
          />
        </Suspense>
      ) : (
        <Loader variant={LoaderVariant.inElement} />
      )}
    </WidgetContainer>
  );
};

export default StixRelationshipsTreeMap;
