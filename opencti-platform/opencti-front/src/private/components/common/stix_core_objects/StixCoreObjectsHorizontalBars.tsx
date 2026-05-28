import React, { ReactNode, Suspense } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import { buildFiltersAndOptionsForWidgets } from '../../../../utils/filters/filtersUtils';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetHorizontalBars from '../../../../components/dashboard/WidgetHorizontalBars';
import useDistributionGraphData from '../../../../utils/hooks/useDistributionGraphData';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import WidgetNoHostEntity from '../../../../components/dashboard/WidgetNoHostEntity';
import { StixCoreObjectsHorizontalBarsDistributionQuery } from '@components/common/stix_core_objects/__generated__/StixCoreObjectsHorizontalBarsDistributionQuery.graphql';
import { Widget, WidgetDataSelection, WidgetHost } from '../../../../utils/widget/widget';
import { DashboardConfig } from '../../../../components/dashboard/dashboard-types';
import { computeStartEndDates } from '../../../../components/dashboard/dashboard-viz-utils';

const stixCoreObjectsHorizontalBarsDistributionQuery = graphql`
    query StixCoreObjectsHorizontalBarsDistributionQuery(
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
              ... on StixRelationship {
                representative {
                  main
                }
              }
              # internal objects
              ... on Creator {
                id
                name
              }
              ... on Group {
                id
                name
              }
              # need colors when available
              ... on Label {
                value
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

interface StixCoreObjectsHorizontalBarsComponentProps {
  queryRef: PreloadedQuery<StixCoreObjectsHorizontalBarsDistributionQuery>;
  dataSelection: Widget['dataSelection'];
  parameters: {
    distributed?: boolean;
  };
}

const StixCoreObjectsHorizontalBarsComponent = ({
  queryRef,
  dataSelection,
  parameters,
}: StixCoreObjectsHorizontalBarsComponentProps) => {
  const { t_i18n } = useFormatter();
  const { buildWidgetProps } = useDistributionGraphData();
  const data = usePreloadedQuery(
    stixCoreObjectsHorizontalBarsDistributionQuery,
    queryRef,
  );
  const selection = dataSelection[0];
  const distribution = data?.stixCoreObjectsDistribution ?? [];

  if (distribution.length === 0) {
    return <WidgetNoData />;
  }
  const { series, redirectionUtils } = buildWidgetProps(
    distribution,
    selection,
    t_i18n('Number of entities'),
  );

  return (
    <WidgetHorizontalBars
      series={series}
      distributed={parameters.distributed}
      redirectionUtils={redirectionUtils}
    />
  );
};

interface StixCoreObjectsHorizontalBarsProps {
  variant?: string;
  height?: number;
  dataSelection: Widget['dataSelection'];
  parameters?: {
    title?: string;
    distributed?: boolean;
  };
  popover?: ReactNode;
  host?: WidgetHost;
  config: DashboardConfig;
  refreshRate?: number | null;
}

const DATA_SELECTION_TYPES = ['Stix-Core-Object'];

const buildQueryVariables = (
  resolvedDataSelection: WidgetDataSelection[],
  config: DashboardConfig,
): StixCoreObjectsHorizontalBarsDistributionQuery['variables'] => {
  const selection = resolvedDataSelection[0];

  const dateAttribute = selection.date_attribute?.length
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
    filters,
    limit: selection.number ?? 10,
  };
};

const StixCoreObjectsHorizontalBars = ({
  variant,
  height,
  dataSelection,
  parameters = {},
  popover,
  host,
  config,
  refreshRate = null,
}: StixCoreObjectsHorizontalBarsProps) => {
  const { t_i18n } = useFormatter();
  const { resolvedDataSelection, isMissingHostEntity, isPreviewMode, queryRef } = useDashboardViz<StixCoreObjectsHorizontalBarsDistributionQuery>({
    perspective: 'entities',
    dataSelection,
    host,
    refreshRate,
    query: stixCoreObjectsHorizontalBarsDistributionQuery,
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
      title={parameters.title ?? t_i18n('Distribution of entities')}
      variant={variant}
      action={popover}
      showPreviewTag={isPreviewMode}
    >
      {queryRef && (
        <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <StixCoreObjectsHorizontalBarsComponent
            queryRef={queryRef}
            dataSelection={resolvedDataSelection}
            parameters={parameters}
          />
        </Suspense>
      )}
    </WidgetContainer>
  );
};

export default StixCoreObjectsHorizontalBars;
