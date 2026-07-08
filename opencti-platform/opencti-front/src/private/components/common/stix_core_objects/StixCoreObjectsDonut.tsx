import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetDonut from '../../../../components/dashboard/WidgetDonut';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { ReactNode, Suspense } from 'react';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import WidgetNoHostEntity from '../../../../components/dashboard/WidgetNoHostEntity';
import { StixCoreObjectsDonutDistributionQuery } from './__generated__/StixCoreObjectsDonutDistributionQuery.graphql';
import { Widget, WidgetDataSelection, WidgetHost } from '../../../../utils/widget/widget';
import { DashboardConfig } from '../../../../components/dashboard/dashboard-types';
import { computeStartEndDates } from '../../../../components/dashboard/dashboardVizUtils';
import { buildFiltersAndOptionsForWidgets, normalizeFilterGroupForBackend } from '../../../../utils/filters/filtersUtils';

const stixCoreObjectsDonutDistributionQuery = graphql`
  query StixCoreObjectsDonutDistributionQuery(
    $objectId: [String]
    $relationship_type: [String]
    $toTypes: [String]
    $elementWithTargetTypes: [String]
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
      elementWithTargetTypes: $elementWithTargetTypes
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

interface StixCoreObjectsDonutComponentProps {
  queryRef: PreloadedQuery<StixCoreObjectsDonutDistributionQuery>;
  dataSelection: Widget['dataSelection'];
}

const StixCoreObjectsDonutComponent = ({
  queryRef,
  dataSelection,
}: StixCoreObjectsDonutComponentProps) => {
  const { stixCoreObjectsDistribution } = usePreloadedQuery(
    stixCoreObjectsDonutDistributionQuery,
    queryRef,
  );
  const selection = dataSelection[0];
  const data = stixCoreObjectsDistribution ?? [];

  return data.length === 0 ? (
    <WidgetNoData />
  ) : (
    <WidgetDonut
      data={data}
      groupBy={selection.attribute ?? 'entity_type'}
    />
  );
};

interface StixCoreObjectsDonutProps {
  variant?: string;
  height?: number;
  dataSelection: Widget['dataSelection'];
  parameters?: { title?: string };
  popover?: ReactNode;
  host?: WidgetHost;
  config: DashboardConfig;
  refreshRate?: number | null;
  withoutTitle?: boolean;
}

const DATA_SELECTION_TYPES = ['Stix-Core-Object'];

const buildQueryVariables = (
  resolvedDataSelection: WidgetDataSelection[],
  config: DashboardConfig,
): StixCoreObjectsDonutDistributionQuery['variables'] => {
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
    field: selection.attribute ?? 'entity_type',
    operation: 'count',
    startDate,
    endDate,
    dateAttribute,
    filters: normalizeFilterGroupForBackend(filters),
    limit: selection.number ?? 10,
  };
};

const StixCoreObjectsDonut = ({
  variant,
  height,
  dataSelection,
  parameters = {},
  withoutTitle = false,
  popover,
  config,
  refreshRate = null,
  host,
}: StixCoreObjectsDonutProps) => {
  const { t_i18n } = useFormatter();
  const { resolvedDataSelection, isMissingHostEntity, isPreviewMode, queryRef } = useDashboardViz<StixCoreObjectsDonutDistributionQuery>({
    perspective: 'entities',
    dataSelection,
    host,
    refreshRate,
    query: stixCoreObjectsDonutDistributionQuery,
    config,
    buildQueryVariables,
  });

  const defaultTitle = withoutTitle ? undefined : t_i18n('Distribution of entities');

  const renderContent = () => {
    if (isMissingHostEntity) {
      return <WidgetNoHostEntity host={host} />;
    }

    if (!queryRef) return null;

    return (
      <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
        <StixCoreObjectsDonutComponent
          queryRef={queryRef}
          dataSelection={resolvedDataSelection}
        />
      </Suspense>
    );
  };

  return (
    <WidgetContainer
      padding="small"
      height={height}
      title={parameters.title ?? defaultTitle}
      variant={variant}
      action={popover}
      showPreviewTag={isPreviewMode}
    >
      {renderContent()}
    </WidgetContainer>
  );
};

export default StixCoreObjectsDonut;
