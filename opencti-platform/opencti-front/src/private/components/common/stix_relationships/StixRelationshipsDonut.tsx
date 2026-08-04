import React, { ReactNode, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import ApexCharts from 'apexcharts';
import { useFormatter } from '../../../../components/i18n';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetDonut from '../../../../components/dashboard/WidgetDonut';
import type { WidgetDataSelection, WidgetHost, WidgetParameters } from '../../../../utils/widget/widget';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import WidgetRenderContent from '../../../../components/dashboard/WidgetRenderContent';
import { StixRelationshipsDonutDistributionQuery } from '@components/common/stix_relationships/__generated__/StixRelationshipsDonutDistributionQuery.graphql';
import { DashboardConfig } from '../../../../components/dashboard/dashboard-types';
import { buildRelationshipSingleWidgetBaseQueryVariables } from '../../../../components/dashboard/dashboardVizUtils';

export const stixRelationshipsDonutsDistributionQuery = graphql`
  query StixRelationshipsDonutDistributionQuery(
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
        ... on StixRelationship {
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

interface StixRelationshipsDonutComponentProps {
  queryRef: PreloadedQuery<StixRelationshipsDonutDistributionQuery>;
  dataSelection: WidgetDataSelection[];
  onMounted: (chart: unknown) => void;
}

const StixRelationshipsDonutComponent = ({
  queryRef,
  dataSelection,
  onMounted,
}: StixRelationshipsDonutComponentProps) => {
  const data = usePreloadedQuery(
    stixRelationshipsDonutsDistributionQuery,
    queryRef,
  );

  if (!data?.stixRelationshipsDistribution?.length) {
    return <WidgetNoData />;
  }
  const selection = dataSelection[0];
  return (
    <WidgetDonut
      data={data.stixRelationshipsDistribution}
      groupBy={selection.attribute ?? 'entity_type'}
      onMounted={onMounted}
    />
  );
};

const buildQueryVariables = (
  resolvedDataSelection: WidgetDataSelection[],
  config: DashboardConfig,
): StixRelationshipsDonutDistributionQuery['variables'] => {
  const selection = resolvedDataSelection[0];
  const { filters, dynamicFrom, dynamicTo } = buildRelationshipSingleWidgetBaseQueryVariables(selection, config);

  return {
    field: selection.attribute ?? 'entity_type',
    operation: 'count',
    limit: selection.number ?? 10,
    filters,
    isTo: selection.isTo,
    dynamicFrom,
    dynamicTo,
  };
};

interface StixRelationshipsDonutProps {
  variant?: string;
  height?: number;
  field?: string;
  dataSelection: WidgetDataSelection[];
  parameters?: WidgetParameters;
  popover?: ReactNode;
  host?: WidgetHost;
  config: DashboardConfig;
  refreshRate?: number | null;
}

const StixRelationshipsDonut = ({
  variant,
  height,
  dataSelection,
  parameters = {},
  popover,
  host,
  config,
  refreshRate = null,
}: StixRelationshipsDonutProps) => {
  const { t_i18n } = useFormatter();
  const [chart, setChart] = useState<ApexCharts>();
  const { resolvedDataSelection, isMissingHostEntity, isMissingSavedFilters, isPreviewMode, queryRef } = useDashboardViz<StixRelationshipsDonutDistributionQuery>({
    perspective: 'relationships',
    dataSelection,
    host,
    refreshRate,
    query: stixRelationshipsDonutsDistributionQuery,
    config,
    buildQueryVariables,
  });

  return (
    <WidgetContainer
      padding="small"
      height={height}
      title={parameters.title ?? t_i18n('Relationships distribution')}
      variant={variant}
      chart={chart}
      action={popover}
      showPreviewTag={isPreviewMode}
    >
      <WidgetRenderContent
        isMissingHostEntity={isMissingHostEntity}
        isMissingSavedFilters={isMissingSavedFilters}
        queryRef={queryRef}
        host={host}
      >
        <StixRelationshipsDonutComponent
          queryRef={queryRef!}
          dataSelection={resolvedDataSelection}
          onMounted={(chart) => setChart(chart as ApexCharts)}
        />
      </WidgetRenderContent>
    </WidgetContainer>
  );
};

export default StixRelationshipsDonut;
