import React, { ReactNode, Suspense } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import { getMainRepresentative, isFieldForIdentifier } from '../../../../utils/defaultRepresentatives';
import useGranted, { SETTINGS_SETACCESSES } from '../../../../utils/hooks/useGranted';
import { buildFiltersAndOptionsForWidgets, sanitizeFilterGroupKeysForBackend } from '../../../../utils/filters/filtersUtils';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetDistributionList from '../../../../components/dashboard/WidgetDistributionList';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import WidgetNoHostEntity from '../../../../components/dashboard/WidgetNoHostEntity';
import { WidgetDataSelection, WidgetHost } from '../../../../utils/widget/widget';
import { StixRelationshipsDistributionListDistributionQuery } from '@components/common/stix_relationships/__generated__/StixRelationshipsDistributionListDistributionQuery.graphql';
import { DashboardConfig } from '../../../../components/dashboard/dashboard-types';
import { computeStartEndDates } from '../../../../components/dashboard/dashboard-viz-utils';

const stixRelationshipsDistributionListDistributionQuery = graphql`
  query StixRelationshipsDistributionListDistributionQuery(
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
        # objects without representative
        ... on Creator {
          name
        }
        ... on Group {
          name
        }
        ... on Workspace {
          name
          type
        }
      }
    }
  }
`;

interface StixRelationshipsDistributionListComponentProps {
  queryRef: PreloadedQuery<StixRelationshipsDistributionListDistributionQuery>;
  dataSelection: WidgetDataSelection[];
  hasSetAccess: boolean;
}

const StixRelationshipsDistributionListComponent = ({
  queryRef,
  dataSelection,
  hasSetAccess,
}: StixRelationshipsDistributionListComponentProps) => {
  const data = usePreloadedQuery(
    stixRelationshipsDistributionListDistributionQuery,
    queryRef,
  );
  const selection = dataSelection[0];
  const raw = data?.stixRelationshipsDistribution ?? [];

  if (!raw.length) {
    return <WidgetNoData />;
  }
  const formatted = raw.map((n) => {
    let label = n?.label;
    let id: string | null = null;
    let type = n?.label;
    if (isFieldForIdentifier(selection.attribute ?? undefined)) {
      label = getMainRepresentative(n?.entity);
      id = n?.entity?.id ?? null;
      type = n?.entity?.entity_type;
    }
    return {
      label,
      value: n?.value,
      id,
      type,
    };
  });
  return (
    <WidgetDistributionList
      data={formatted}
      hasSettingAccess={hasSetAccess}
    />
  );
};

const buildQueryVariables = (
  resolvedDataSelection: WidgetDataSelection[],
  config: DashboardConfig,
): StixRelationshipsDistributionListDistributionQuery['variables'] => {
  const selection = resolvedDataSelection[0];
  const dateAttribute = selection.date_attribute?.length
    ? selection.date_attribute
    : 'created_at';
  const { startDate, endDate } = computeStartEndDates(config);
  const { filters } = buildFiltersAndOptionsForWidgets(
    selection.filters,
    {
      startDate,
      endDate,
      dateAttribute,
      isKnowledgeRelationshipWidget: true,
    },
  );
  return {
    field: selection.attribute ?? 'entity_type',
    operation: 'count',
    startDate,
    endDate,
    dateAttribute,
    limit: selection.number ?? 10,
    isTo: selection.isTo ?? undefined,
    filters: filters ? sanitizeFilterGroupKeysForBackend(filters) : undefined,
    dynamicFrom: selection.dynamicFrom
      ? (selection.dynamicFrom as unknown as StixRelationshipsDistributionListDistributionQuery['variables']['dynamicFrom'])
      : null,
    dynamicTo: selection.dynamicTo
      ? (selection.dynamicTo as unknown as StixRelationshipsDistributionListDistributionQuery['variables']['dynamicTo'])
      : null,
  };
};

interface StixRelationshipsDistributionListProps {
  variant?: string;
  height?: number;
  dataSelection: WidgetDataSelection[];
  parameters?: { title?: string };
  popover?: ReactNode;
  host?: WidgetHost;
  config: DashboardConfig;
  refreshRate?: number | null;
}

const StixRelationshipsDistributionList = ({
  variant,
  height,
  dataSelection,
  parameters = {},
  popover,
  host,
  config,
  refreshRate = null,
}: StixRelationshipsDistributionListProps) => {
  const { t_i18n } = useFormatter();
  const hasSetAccess = useGranted([SETTINGS_SETACCESSES]);
  const { resolvedDataSelection, isMissingHostEntity, isPreviewMode, queryRef } = useDashboardViz<StixRelationshipsDistributionListDistributionQuery>({
    perspective: 'relationships',
    dataSelection,
    host,
    refreshRate,
    query: stixRelationshipsDistributionListDistributionQuery,
    config,
    buildQueryVariables,
  });

  const renderContent = () => {
    if (isMissingHostEntity) {
      return <WidgetNoHostEntity host={host} />;
    }

    if (!queryRef) return null;

    return (
      <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
        <StixRelationshipsDistributionListComponent
          queryRef={queryRef}
          dataSelection={resolvedDataSelection}
          hasSetAccess={hasSetAccess}
        />
      </Suspense>
    );
  };

  return (
    <WidgetContainer
      height={height}
      title={parameters.title ?? t_i18n('Relationships distribution')}
      variant={variant}
      action={popover}
      showPreviewTag={isPreviewMode}
    >
      <div style={{ height: '100%' }}>
        {renderContent()}
      </div>
    </WidgetContainer>
  );
};

export default StixRelationshipsDistributionList;
