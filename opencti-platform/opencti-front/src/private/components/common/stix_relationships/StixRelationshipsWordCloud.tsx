import React, { ReactNode } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetWordCloud from '../../../../components/dashboard/WidgetWordCloud';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import WidgetRenderContent from '../../../../components/dashboard/WidgetRenderContent';
import { StixRelationshipsWordCloudDistributionQuery } from '@components/common/stix_relationships/__generated__/StixRelationshipsWordCloudDistributionQuery.graphql';
import { WidgetDataSelection, WidgetHost, WidgetParameters } from '../../../../utils/widget/widget';
import { DashboardConfig } from '../../../../components/dashboard/dashboard-types';
import { buildRelationshipSingleWidgetBaseQueryVariables } from '../../../../components/dashboard/dashboardVizUtils';

export const stixRelationshipsWordCloudsDistributionQuery = graphql`
  query StixRelationshipsWordCloudDistributionQuery(
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

interface StixRelationshipsWordCloudComponentProps {
  queryRef: PreloadedQuery<StixRelationshipsWordCloudDistributionQuery>;
  dataSelection: WidgetDataSelection[];
}

const StixRelationshipsWordCloudComponent = ({
  queryRef,
  dataSelection,
}: StixRelationshipsWordCloudComponentProps) => {
  const data = usePreloadedQuery(
    stixRelationshipsWordCloudsDistributionQuery,
    queryRef,
  );

  const distribution = data?.stixRelationshipsDistribution ?? [];
  const selection = dataSelection[0];

  if (!distribution.length) {
    return <WidgetNoData />;
  }

  return (
    <WidgetWordCloud
      data={distribution}
      groupBy={selection.attribute ?? 'entity_type'}
    />
  );
};

const buildQueryVariables = (
  resolvedDataSelection: WidgetDataSelection[],
  config: DashboardConfig,
): StixRelationshipsWordCloudDistributionQuery['variables'] => {
  const selection = resolvedDataSelection[0];
  const { startDate, endDate, dateAttribute, filters, dynamicFrom, dynamicTo } = buildRelationshipSingleWidgetBaseQueryVariables(selection, config);

  return {
    field: selection.attribute ?? 'entity_type',
    operation: 'count',
    startDate,
    endDate,
    dateAttribute,
    limit: selection.number ?? 10,
    filters,
    isTo: selection.isTo,
    dynamicFrom,
    dynamicTo,
  };
};

interface StixRelationshipsWordCloudProps {
  dataSelection: WidgetDataSelection[];
  parameters?: WidgetParameters;
  variant?: string;
  height?: number;
  popover?: ReactNode;
  host?: WidgetHost;
  config: DashboardConfig;
  refreshRate?: number | null;
}
const StixRelationshipsWordCloud = ({
  variant,
  height,
  dataSelection,
  parameters = {},
  popover,
  host,
  config,
  refreshRate = null,
}: StixRelationshipsWordCloudProps) => {
  const { t_i18n } = useFormatter();
  const { resolvedDataSelection, isMissingHostEntity, isMissingSavedFilters, isPreviewMode, queryRef } = useDashboardViz<StixRelationshipsWordCloudDistributionQuery>({
    perspective: 'relationships',
    dataSelection,
    host,
    refreshRate,
    query: stixRelationshipsWordCloudsDistributionQuery,
    config,
    buildQueryVariables,
  });

  return (
    <WidgetContainer
      height={height}
      title={parameters.title ?? t_i18n('Relationships distribution')}
      variant={variant}
      action={popover}
      showPreviewTag={isPreviewMode}
    >
      <WidgetRenderContent
        isMissingHostEntity={isMissingHostEntity}
        isMissingSavedFilters={isMissingSavedFilters}
        queryRef={queryRef}
        host={host}
      >
        <StixRelationshipsWordCloudComponent
          queryRef={queryRef!}
          dataSelection={resolvedDataSelection}
        />
      </WidgetRenderContent>
    </WidgetContainer>
  );
};

export default StixRelationshipsWordCloud;
