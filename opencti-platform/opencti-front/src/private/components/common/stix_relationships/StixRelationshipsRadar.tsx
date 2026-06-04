import React, { ReactNode, Suspense, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import { buildFiltersAndOptionsForWidgets, GqlFilterGroup } from '../../../../utils/filters/filtersUtils';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetRadar from '../../../../components/dashboard/WidgetRadar';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import WidgetNoHostEntity from '../../../../components/dashboard/WidgetNoHostEntity';
import { StixRelationshipsRadarDistributionQuery } from '@components/common/stix_relationships/__generated__/StixRelationshipsRadarDistributionQuery.graphql';
import { WidgetDataSelection, WidgetHost, WidgetParameters } from '../../../../utils/widget/widget';
import { DashboardConfig } from '../../../../components/dashboard/dashboard-types';
import { computeStartEndDates } from '../../../../components/dashboard/dashboard-viz-utils';

const stixRelationshipsRadarsDistributionQuery = graphql`
  query StixRelationshipsRadarDistributionQuery(
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
        # internal objects
        ... on Creator {
          name
        }
        ... on Group {
          name
        }
        # need colors when available
        ... on Label {
          color
        }
        ... on MarkingDefinition {
          x_opencti_color
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

interface StixRelationshipsRadarComponentProps {
  queryRef: PreloadedQuery<StixRelationshipsRadarDistributionQuery>;
  dataSelection: WidgetDataSelection[];
  parameters?: WidgetParameters;
  onMounted: (chart: ApexCharts) => void;
}

const StixRelationshipsRadarComponent = ({
  queryRef,
  dataSelection,
  onMounted,
}: StixRelationshipsRadarComponentProps) => {
  const { t_i18n } = useFormatter();
  const data = usePreloadedQuery(
    stixRelationshipsRadarsDistributionQuery,
    queryRef,
  );

  if (!data?.stixRelationshipsDistribution?.length) {
    return <WidgetNoData />;
  }

  const selection = dataSelection[0];
  const finalField = selection.attribute ?? 'entity_type';

  return (
    <WidgetRadar
      data={data.stixRelationshipsDistribution}
      label={selection.label ?? t_i18n('Number of entities')}
      groupBy={finalField}
      onMounted={onMounted}
    />
  );
};

const buildQueryVariables = (
  resolvedDataSelection: WidgetDataSelection[],
  config: DashboardConfig,
): StixRelationshipsRadarDistributionQuery['variables'] => {
  const selection = resolvedDataSelection[0];
  const dateAttribute
    = selection.date_attribute?.length ? selection.date_attribute : 'created_at';
  const { startDate, endDate } = computeStartEndDates(config);
  const { filters } = buildFiltersAndOptionsForWidgets(
    selection.filters,
    { isKnowledgeRelationshipWidget: true },
  );

  type QueryFilterGroup
    = StixRelationshipsRadarDistributionQuery['variables']['dynamicFrom'];

  return {
    field: selection.attribute ?? 'entity_type',
    operation: 'count',
    startDate,
    endDate,
    dateAttribute,
    limit: selection.number ?? 10,
    filters: filters as unknown as GqlFilterGroup,
    isTo: selection.isTo,
    dynamicFrom: selection.dynamicFrom as unknown as QueryFilterGroup,
    dynamicTo: selection.dynamicTo as unknown as QueryFilterGroup,
  };
};

interface StixRelationshipsRadarProps {
  title?: string;
  variant?: string;
  height?: number;
  dataSelection: WidgetDataSelection[];
  parameters?: WidgetParameters;
  popover?: ReactNode;
  host?: WidgetHost;
  config: DashboardConfig;
  refreshRate?: number | null;
}

const StixRelationshipsRadar = ({
  title,
  variant,
  height,
  dataSelection,
  parameters = {},
  popover,
  host,
  config,
  refreshRate = null,
}: StixRelationshipsRadarProps) => {
  const { t_i18n } = useFormatter();
  const [chart, setChart] = useState<ApexCharts>();
  const { resolvedDataSelection, isMissingHostEntity, isPreviewMode, queryRef } = useDashboardViz<StixRelationshipsRadarDistributionQuery>({
    perspective: 'relationships',
    dataSelection,
    host,
    refreshRate,
    query: stixRelationshipsRadarsDistributionQuery,
    config,
    buildQueryVariables,
  });

  if (isMissingHostEntity) {
    return <WidgetNoHostEntity host={host} />;
  }

  return (
    <WidgetContainer
      padding="small"
      height={height}
      title={parameters.title ?? title ?? t_i18n('Relationships distribution')}
      variant={variant}
      chart={chart}
      action={popover}
      showPreviewTag={isPreviewMode}
    >
      {queryRef ? (
        <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <StixRelationshipsRadarComponent
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

export default StixRelationshipsRadar;
