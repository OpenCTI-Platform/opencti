import React, { ReactNode, Suspense } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetWordCloud from '../../../../components/dashboard/WidgetWordCloud';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import WidgetNoHostEntity from '../../../../components/dashboard/WidgetNoHostEntity';
import { StixCoreObjectsWordCloudDistributionQuery } from '@components/common/stix_core_objects/__generated__/StixCoreObjectsWordCloudDistributionQuery.graphql';
import { WidgetDataSelection, WidgetHost, WidgetParameters } from '../../../../utils/widget/widget';
import { DashboardConfig } from '../../../../components/dashboard/dashboard-types';
import { computeStartEndDates } from '../../../../components/dashboard/dashboard-viz-utils';
import { buildFiltersAndOptionsForWidgets, normalizeFilterGroupForBackend } from '../../../../utils/filters/filtersUtils';

const stixCoreObjectsWordCloudDistributionQuery = graphql`
  query StixCoreObjectsWordCloudDistributionQuery(
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

interface StixCoreObjectsWordCloudComponentProps {
  queryRef: PreloadedQuery<StixCoreObjectsWordCloudDistributionQuery>;
  dataSelection: WidgetDataSelection[];
}

const StixCoreObjectsWordCloudComponent = ({
  queryRef,
  dataSelection,
}: StixCoreObjectsWordCloudComponentProps) => {
  const { stixCoreObjectsDistribution } = usePreloadedQuery(
    stixCoreObjectsWordCloudDistributionQuery,
    queryRef,
  );
  const data = stixCoreObjectsDistribution ?? [];
  const groupBy = dataSelection?.[0]?.attribute ?? 'entity_type';

  if (data.length === 0) {
    return <WidgetNoData />;
  }
  return (
    <WidgetWordCloud
      data={data}
      groupBy={groupBy}
    />
  );
};

const DATA_SELECTION_TYPES = ['Stix-Core-Object'];

const buildQueryVariables = (
  resolvedDataSelection: WidgetDataSelection[],
  config: DashboardConfig,
): StixCoreObjectsWordCloudDistributionQuery['variables'] => {
  const selection = resolvedDataSelection[0];
  const { startDate, endDate } = computeStartEndDates(config);
  const dateAttribute
    = selection.date_attribute?.length
      ? selection.date_attribute
      : 'created_at';
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

interface StixCoreObjectsWordCloudProps {
  variant?: string;
  height?: number;
  dataSelection: WidgetDataSelection[];
  parameters?: WidgetParameters;
  popover?: ReactNode;
  host?: WidgetHost;
  config: DashboardConfig;
  refreshRate?: number | null;
}

const StixCoreObjectsWordCloud = ({
  variant,
  height,
  dataSelection,
  parameters = {},
  popover,
  host,
  config,
  refreshRate = null,
}: StixCoreObjectsWordCloudProps) => {
  const { t_i18n } = useFormatter();
  const { resolvedDataSelection, isMissingHostEntity, isPreviewMode, queryRef } = useDashboardViz<StixCoreObjectsWordCloudDistributionQuery>({
    perspective: 'entities',
    dataSelection,
    host,
    refreshRate,
    query: stixCoreObjectsWordCloudDistributionQuery,
    config,
    buildQueryVariables,
  });

  const renderContent = () => {
    if (isMissingHostEntity) {
      return <WidgetNoHostEntity host={host} />;
    }

    if (!queryRef) {
      return <Loader variant={LoaderVariant.inElement} />;
    }

    return (
      <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
        <StixCoreObjectsWordCloudComponent
          queryRef={queryRef}
          dataSelection={resolvedDataSelection}
        />
      </Suspense>
    );
  };

  return (
    <WidgetContainer
      height={height}
      title={parameters?.title ?? t_i18n('Distribution of entities')}
      variant={variant}
      action={popover}
      showPreviewTag={isPreviewMode}
    >
      {renderContent()}
    </WidgetContainer>
  );
};

export default StixCoreObjectsWordCloud;
