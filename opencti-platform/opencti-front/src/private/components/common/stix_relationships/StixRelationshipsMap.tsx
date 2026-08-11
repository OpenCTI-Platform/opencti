import React, { ReactNode } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import LocationMiniMapTargets from '../location/LocationMiniMapTargets';
import { computeLevel } from '../../../../utils/Number';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import WidgetRenderContent from '../../../../components/dashboard/WidgetRenderContent';
import {
  StixRelationshipsMapStixRelationshipsDistributionQuery,
} from '@components/common/stix_relationships/__generated__/StixRelationshipsMapStixRelationshipsDistributionQuery.graphql';
import { WidgetDataSelection, WidgetHost, WidgetParameters } from '../../../../utils/widget/widget';
import { DashboardConfig } from '../../../../components/dashboard/dashboard-types';
import { buildRelationshipSingleWidgetBaseQueryVariables } from '../../../../components/dashboard/dashboardVizUtils';

export const stixRelationshipsMapStixRelationshipsDistributionQuery = graphql`
  query StixRelationshipsMapStixRelationshipsDistributionQuery(
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
          entity_type
        }
        ... on BasicRelationship {
          entity_type
        }
        ... on Country {
          name
          x_opencti_aliases
          latitude
          longitude
        }
        ... on City {
          name
          x_opencti_aliases
          latitude
          longitude
        }
      }
    }
  }
`;

interface StixRelationshipsMapComponentProps {
  queryRef: PreloadedQuery<StixRelationshipsMapStixRelationshipsDistributionQuery>;
  dataSelection: WidgetDataSelection[];
}

const StixRelationshipsMapComponent = ({
  queryRef,
  dataSelection,
}: StixRelationshipsMapComponentProps) => {
  const data = usePreloadedQuery(
    stixRelationshipsMapStixRelationshipsDistributionQuery,
    queryRef,
  );
  const distribution = data?.stixRelationshipsDistribution ?? [];
  const selection = dataSelection[0];

  if (!distribution.length) {
    return <WidgetNoData />;
  }

  const safeDistribution = distribution.filter(
    (d): d is NonNullable<typeof d> => Boolean(d),
  );

  const values = safeDistribution
    .map((d) => d.value ?? 0)
    .filter((v): v is number => typeof v === 'number');

  const min = values[0] ?? 0;
  const max = values[values.length - 1];

  const countries = safeDistribution
    .filter((n) => n.entity?.entity_type === 'Country')
    .map((x) => ({
      ...x.entity,
      level: computeLevel(
        x.value ?? 0,
        max,
        min + 1,
      ),
    }));

  const cities = safeDistribution
    .filter((n) => n.entity?.entity_type === 'City')
    .map((x) => x.entity);

  return (
    <LocationMiniMapTargets
      center={[
        selection.centerLat ?? 48.8566969,
        selection.centerLng ?? 2.3514616,
      ]}
      countries={countries}
      cities={cities}
      zoom={selection.zoom ?? 2}
    />
  );
};

const buildQueryVariables = (
  resolvedDataSelection: WidgetDataSelection[],
  config: DashboardConfig,
): StixRelationshipsMapStixRelationshipsDistributionQuery['variables'] => {
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

interface StixRelationshipsMapProps {
  dataSelection: WidgetDataSelection[];
  parameters?: WidgetParameters;
  variant?: string;
  height?: number;
  popover?: ReactNode;
  host?: WidgetHost;
  config: DashboardConfig;
  refreshRate?: number | null;
}

const StixRelationshipsMap = ({
  variant,
  height,
  dataSelection,
  parameters = {},
  popover,
  host,
  config,
  refreshRate = null,
}: StixRelationshipsMapProps) => {
  const { t_i18n } = useFormatter();
  const { resolvedDataSelection, isMissingHostEntity, isMissingSavedFilters, isPreviewMode, queryRef } = useDashboardViz<StixRelationshipsMapStixRelationshipsDistributionQuery>({
    perspective: 'relationships',
    dataSelection,
    host,
    refreshRate,
    query: stixRelationshipsMapStixRelationshipsDistributionQuery,
    config,
    buildQueryVariables,
  });

  return (
    <WidgetContainer
      padding="none"
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
        <StixRelationshipsMapComponent
          queryRef={queryRef!}
          dataSelection={resolvedDataSelection}
        />
      </WidgetRenderContent>
    </WidgetContainer>
  );
};

export default StixRelationshipsMap;
