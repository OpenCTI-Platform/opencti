import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetHorizontalBars from '../../../../components/dashboard/WidgetHorizontalBars';
import useDistributionGraphData from '../../../../utils/hooks/useDistributionGraphData';
import { ReactNode, useState } from 'react';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import WidgetRenderContent from '../../../../components/dashboard/WidgetRenderContent';
import { StixRelationshipsHorizontalBarsDistributionQuery } from './__generated__/StixRelationshipsHorizontalBarsDistributionQuery.graphql';
import { WidgetDataSelection, WidgetHost, WidgetParameters } from '../../../../utils/widget/widget';
import { DashboardConfig } from '../../../../components/dashboard/dashboard-types';
import ApexCharts from 'apexcharts';
import { buildRelationshipSingleWidgetBaseQueryVariables } from '../../../../components/dashboard/dashboardVizUtils';

export const stixRelationshipsHorizontalBarsDistributionQuery = graphql`
  query StixRelationshipsHorizontalBarsDistributionQuery(
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

interface StixRelationshipsHorizontalBarsComponentProps {
  queryRef: PreloadedQuery<StixRelationshipsHorizontalBarsDistributionQuery>;
  dataSelection: WidgetDataSelection[];
  parameters?: WidgetParameters;
  onMounted: (chart: unknown) => void;
}

const StixRelationshipsHorizontalBarsComponent = ({
  queryRef,
  dataSelection,
  parameters,
  onMounted,
}: StixRelationshipsHorizontalBarsComponentProps) => {
  const data = usePreloadedQuery(
    stixRelationshipsHorizontalBarsDistributionQuery,
    queryRef,
  );
  const { buildWidgetProps } = useDistributionGraphData();

  if (!data?.stixRelationshipsDistribution?.length) {
    return <WidgetNoData />;
  }

  const selection = dataSelection[0];
  const { series, redirectionUtils } = buildWidgetProps(
    data.stixRelationshipsDistribution,
    selection,
    'Number of relationships',
  );

  return (
    <WidgetHorizontalBars
      series={series}
      distributed={parameters?.distributed ?? undefined}
      onMounted={onMounted}
      redirectionUtils={redirectionUtils}
    />
  );
};

const buildQueryVariables = (
  resolvedDataSelection: WidgetDataSelection[],
  config: DashboardConfig,
): StixRelationshipsHorizontalBarsDistributionQuery['variables'] => {
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

interface StixRelationshipsHorizontalBarsProps {
  variant?: string;
  height?: number;
  dataSelection: WidgetDataSelection[];
  parameters?: WidgetParameters;
  popover?: ReactNode;
  host?: WidgetHost;
  config: DashboardConfig;
  refreshRate?: number | null;
}

const StixRelationshipsHorizontalBars = ({
  variant,
  height,
  dataSelection,
  parameters = {},
  popover,
  host,
  config,
  refreshRate = null,
}: StixRelationshipsHorizontalBarsProps) => {
  const { t_i18n } = useFormatter();
  const [chart, setChart] = useState<ApexCharts>();
  const { resolvedDataSelection, isMissingHostEntity, isMissingSavedFilters, isPreviewMode, queryRef } = useDashboardViz<StixRelationshipsHorizontalBarsDistributionQuery>({
    perspective: 'relationships',
    dataSelection,
    host,
    refreshRate,
    query: stixRelationshipsHorizontalBarsDistributionQuery,
    config,
    buildQueryVariables,
  });

  return (
    <WidgetContainer
      padding="small"
      height={height}
      title={parameters.title ?? t_i18n('Distribution of entities')}
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
        <StixRelationshipsHorizontalBarsComponent
          queryRef={queryRef!}
          dataSelection={resolvedDataSelection}
          parameters={parameters}
          onMounted={(chart) => setChart(chart as ApexCharts)}
        />
      </WidgetRenderContent>
    </WidgetContainer>
  );
};

export default StixRelationshipsHorizontalBars;
