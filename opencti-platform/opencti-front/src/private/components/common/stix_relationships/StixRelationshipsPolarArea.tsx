import React, { ReactNode, Suspense, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import { buildFiltersAndOptionsForWidgets, normalizeFilterGroupForBackend } from '../../../../utils/filters/filtersUtils';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetPolarArea from '../../../../components/dashboard/WidgetPolarArea';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import WidgetNoHostEntity from '../../../../components/dashboard/WidgetNoHostEntity';
import WidgetNoSavedFilters from 'src/components/dashboard/WidgetNoSavedFilters';
import { StixRelationshipsPolarAreaDistributionQuery } from './__generated__/StixRelationshipsPolarAreaDistributionQuery.graphql';
import { WidgetDataSelection, WidgetHost, WidgetParameters } from '../../../../utils/widget/widget';
import { DashboardConfig } from '../../../../components/dashboard/dashboard-types';
import { computeStartEndDates } from '../../../../components/dashboard/dashboardVizUtils';

const stixRelationshipsPolarAreasDistributionQuery = graphql`
  query StixRelationshipsPolarAreaDistributionQuery(
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

interface StixRelationshipsPolarAreaComponentProps {
  queryRef: PreloadedQuery<StixRelationshipsPolarAreaDistributionQuery>;
  dataSelection: WidgetDataSelection[];
  onMounted: (chart: unknown) => void;
}

const StixRelationshipsPolarAreaComponent = ({
  queryRef,
  dataSelection,
  onMounted,
}: StixRelationshipsPolarAreaComponentProps) => {
  const data = usePreloadedQuery(
    stixRelationshipsPolarAreasDistributionQuery,
    queryRef,
  );

  if (!data?.stixRelationshipsDistribution?.length) {
    return <WidgetNoData />;
  }
  const selection = dataSelection[0];
  const finalField = selection.attribute ?? 'entity_type';

  return (
    <WidgetPolarArea
      data={data.stixRelationshipsDistribution}
      groupBy={finalField}
      onMounted={onMounted}
    />
  );
};

const buildQueryVariables = (
  resolvedDataSelection: WidgetDataSelection[],
  config: DashboardConfig,
): StixRelationshipsPolarAreaDistributionQuery['variables'] => {
  const selection = resolvedDataSelection[0];
  const dateAttribute
    = selection.date_attribute?.length ? selection.date_attribute : 'created_at';
  const { startDate, endDate } = computeStartEndDates(config);
  const { filters } = buildFiltersAndOptionsForWidgets(
    selection.filters,
    { isKnowledgeRelationshipWidget: true },
  );

  return {
    field: selection.attribute ?? 'entity_type',
    operation: 'count',
    startDate,
    endDate,
    dateAttribute,
    limit: selection.number ?? 10,
    filters: normalizeFilterGroupForBackend(filters),
    isTo: selection.isTo,
    dynamicFrom: normalizeFilterGroupForBackend(selection.dynamicFrom),
    dynamicTo: normalizeFilterGroupForBackend(selection.dynamicTo),
  };
};

interface StixRelationshipsPolarAreaProps {
  variant?: string;
  height?: number;
  dataSelection: WidgetDataSelection[];
  parameters?: WidgetParameters;
  popover?: ReactNode;
  host?: WidgetHost;
  config: DashboardConfig;
  refreshRate?: number | null;
}

const StixRelationshipsPolarArea = ({
  variant,
  height,
  dataSelection,
  parameters = {},
  popover,
  host,
  config,
  refreshRate = null,
}: StixRelationshipsPolarAreaProps) => {
  const { t_i18n } = useFormatter();
  const [chart, setChart] = useState<ApexCharts>();
  const { resolvedDataSelection, isMissingHostEntity, isMissingSavedFilters, isPreviewMode, queryRef } = useDashboardViz<StixRelationshipsPolarAreaDistributionQuery>({
    perspective: 'relationships',
    dataSelection,
    host,
    refreshRate,
    query: stixRelationshipsPolarAreasDistributionQuery,
    config,
    buildQueryVariables,
  });

  const renderContent = () => {
    if (isMissingHostEntity) {
      return <WidgetNoHostEntity host={host} />;
    }

    if (isMissingSavedFilters) {
      return <WidgetNoSavedFilters />;
    }

    if (!queryRef) {
      return <Loader variant={LoaderVariant.inElement} />;
    }

    return (
      <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
        <StixRelationshipsPolarAreaComponent
          queryRef={queryRef}
          dataSelection={resolvedDataSelection}
          onMounted={(chart) => setChart(chart as ApexCharts)}
        />
      </Suspense>
    );
  };

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
      {renderContent()}
    </WidgetContainer>
  );
};

export default StixRelationshipsPolarArea;
