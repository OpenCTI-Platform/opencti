import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import React, { CSSProperties, ReactNode, Suspense, useState } from 'react';
import ApexCharts from 'apexcharts';
import { StixCoreObjectsPolarAreaDistributionQuery } from '@components/common/stix_core_objects/__generated__/StixCoreObjectsPolarAreaDistributionQuery.graphql';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import { useFormatter } from '../../../../components/i18n';
import WidgetPolarArea from '../../../../components/dashboard/WidgetPolarArea';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import type { WidgetDataSelection, WidgetHost, WidgetParameters } from '../../../../utils/widget/widget';
import { OpenCTIChartProps } from '../charts/Chart';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import WidgetNoHostEntity from '../../../../components/dashboard/WidgetNoHostEntity';
import { DashboardConfig } from '../../../../components/dashboard/dashboard-types';
import { computeStartEndDates } from '../../../../components/dashboard/dashboard-viz-utils';
import { buildFiltersAndOptionsForWidgets, GqlFilterGroup } from '../../../../utils/filters/filtersUtils';

const stixCoreObjectsPolarAreaDistributionQuery = graphql`
  query StixCoreObjectsPolarAreaDistributionQuery(
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

interface StixCoreObjectsPolarAreaComponentProps {
  dataSelection: WidgetDataSelection[];
  queryRef: PreloadedQuery<StixCoreObjectsPolarAreaDistributionQuery>;
  onMounted?: OpenCTIChartProps['onMounted'];
}

const StixCoreObjectsPolarAreaComponent = ({
  dataSelection,
  queryRef,
  onMounted,
}: StixCoreObjectsPolarAreaComponentProps) => {
  const { stixCoreObjectsDistribution } = usePreloadedQuery(
    stixCoreObjectsPolarAreaDistributionQuery,
    queryRef,
  );
  const data = stixCoreObjectsDistribution ?? [];
  const groupBy = dataSelection?.[0]?.attribute ?? 'entity_type';

  if (data.length === 0) {
    return <WidgetNoData />;
  }
  return (
    <WidgetPolarArea
      data={data}
      groupBy={groupBy}
      onMounted={onMounted}
    />
  );
};

const DATA_SELECTION_TYPES = ['Stix-Core-Object'];

const buildQueryVariables = (
  resolvedDataSelection: WidgetDataSelection[],
  config: DashboardConfig,
): StixCoreObjectsPolarAreaDistributionQuery['variables'] => {
  const selection = resolvedDataSelection[0];
  const { startDate, endDate } = computeStartEndDates(config);
  const dateAttribute
    = selection.date_attribute
      && selection.date_attribute.length > 0
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
    filters: filters as unknown as GqlFilterGroup,
    limit: selection.number ?? 10,
  };
};

interface StixCoreObjectsPolarAreaProps {
  dataSelection: WidgetDataSelection[];
  parameters?: WidgetParameters | null;
  variant?: string;
  height?: CSSProperties['height'];
  popover?: ReactNode;
  host?: WidgetHost;
  config: DashboardConfig;
  refreshRate?: number | null;
}

const StixCoreObjectsPolarArea = ({
  dataSelection,
  parameters,
  height,
  variant,
  popover,
  host,
  config,
  refreshRate = null,
}: StixCoreObjectsPolarAreaProps) => {
  const { t_i18n } = useFormatter();
  const [chart, setChart] = useState<ApexCharts>();
  const { resolvedDataSelection, isMissingHostEntity, isPreviewMode, queryRef } = useDashboardViz<StixCoreObjectsPolarAreaDistributionQuery>({
    perspective: 'entities',
    dataSelection,
    host,
    refreshRate,
    query: stixCoreObjectsPolarAreaDistributionQuery,
    config,
    buildQueryVariables,
  });
  const title = parameters?.title ?? t_i18n('Distribution of entities');

  if (isMissingHostEntity) {
    return <WidgetNoHostEntity host={host} />;
  }
  return (
    <WidgetContainer
      padding="small"
      height={height}
      title={title}
      variant={variant}
      chart={chart}
      action={popover}
      showPreviewTag={isPreviewMode}
    >
      {queryRef ? (
        <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <StixCoreObjectsPolarAreaComponent
            queryRef={queryRef}
            dataSelection={resolvedDataSelection}
            onMounted={setChart}
          />
        </Suspense>
      ) : (
        <Loader variant={LoaderVariant.inElement} />
      )}
    </WidgetContainer>
  );
};

export default StixCoreObjectsPolarArea;
