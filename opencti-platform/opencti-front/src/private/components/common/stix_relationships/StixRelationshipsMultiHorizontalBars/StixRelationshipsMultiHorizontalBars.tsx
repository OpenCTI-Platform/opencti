import React, { CSSProperties, FunctionComponent, Suspense, useEffect, useRef, useState, useTransition } from 'react';
import type { PreloadedQuery } from 'react-relay';
import { graphql, usePreloadedQuery } from 'react-relay';
import ApexCharts from 'apexcharts';
import type { WidgetDataSelection, WidgetHost, WidgetParameters } from '../../../../../utils/widget/widget';
import { useFormatter } from '../../../../../components/i18n';
import { buildFiltersAndOptionsForWidgets, normalizeFilterGroupForBackend } from '../../../../../utils/filters/filtersUtils';
import type { DashboardConfig } from '../../../../../components/dashboard/dashboard-types';
import WidgetContainer from '../../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../../components/dashboard/WidgetNoData';
import WidgetHorizontalBars from '../../../../../components/dashboard/WidgetHorizontalBars';
import Loader, { LoaderVariant } from '../../../../../components/Loader';
import { useQueryLoadingWithLoadQuery } from '../../../../../utils/hooks/useQueryLoading';
import useDashboardViz from '../../../../../components/dashboard/useDashboardViz';
import WidgetNoHostEntity from '../../../../../components/dashboard/WidgetNoHostEntity';
import WidgetNoSavedFilters from '../../../../../components/dashboard/WidgetNoSavedFilters';
import { useStixRelationshipsMultiHorizontalBars } from './useStixRelationshipsMultiHorizontalBars';
import { useDashboardRefreshToken } from '../../../../../components/dashboard/DashboardRefreshContext';
import type {
  StixRelationshipsMultiHorizontalBarsWithRelationshipsDistributionQuery,
} from './__generated__/StixRelationshipsMultiHorizontalBarsWithRelationshipsDistributionQuery.graphql';
import type { StixRelationshipsMultiHorizontalBarsWithEntitiesDistributionQuery } from './__generated__/StixRelationshipsMultiHorizontalBarsWithEntitiesDistributionQuery.graphql';

// ---------------------------------------------------------------------------
// GraphQL queries
// ---------------------------------------------------------------------------

const stixRelationshipsMultiHorizontalBarsWithRelationshipsDistributionQuery = graphql`
  query StixRelationshipsMultiHorizontalBarsWithRelationshipsDistributionQuery(
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
    $subDistributionField: String!
    $subDistributionOperation: StatsOperation!
    $subDistributionStartDate: DateTime
    $subDistributionEndDate: DateTime
    $subDistributionDateAttribute: String
    $subDistributionIsTo: Boolean
    $subDistributionLimit: Int
    $subDistributionElementWithTargetTypes: [String]
    $subDistributionFromId: [String]
    $subDistributionFromRole: String
    $subDistributionFromTypes: [String]
    $subDistributionToId: [String]
    $subDistributionToRole: String
    $subDistributionToTypes: [String]
    $subDistributionRelationshipType: [String]
    $subDistributionConfidences: [Int]
    $subDistributionSearch: String
    $subDistributionFilters: FilterGroup
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
        ... on StixCoreObject {
          stixCoreRelationshipsDistribution(
            field: $subDistributionField
            operation: $subDistributionOperation
            startDate: $subDistributionStartDate
            endDate: $subDistributionEndDate
            dateAttribute: $subDistributionDateAttribute
            isTo: $subDistributionIsTo
            limit: $subDistributionLimit
            elementWithTargetTypes: $subDistributionElementWithTargetTypes
            fromId: $subDistributionFromId
            fromRole: $subDistributionFromRole
            fromTypes: $subDistributionFromTypes
            toId: $subDistributionToId
            toRole: $subDistributionToRole
            toTypes: $subDistributionToTypes
            relationship_type: $subDistributionRelationshipType
            confidences: $subDistributionConfidences
            search: $subDistributionSearch
            filters: $subDistributionFilters
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
              ... on Label {
                color
              }
              ... on MarkingDefinition {
                x_opencti_color
              }
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
      }
    }
  }
`;

const stixRelationshipsMultiHorizontalBarsWithEntitiesDistributionQuery = graphql`
  query StixRelationshipsMultiHorizontalBarsWithEntitiesDistributionQuery(
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
    $subDistributionRelationshipType: [String]
    $subDistributionToTypes: [String]
    $subDistributionField: String!
    $subDistributionStartDate: DateTime
    $subDistributionEndDate: DateTime
    $subDistributionDateAttribute: String
    $subDistributionOperation: StatsOperation!
    $subDistributionLimit: Int
    $subDistributionOrder: String
    $subDistributionTypes: [String]
    $subDistributionFilters: FilterGroup
    $subDistributionSearch: String
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
        ... on StixCoreObject {
          stixCoreObjectsDistribution(
            relationship_type: $subDistributionRelationshipType
            toTypes: $subDistributionToTypes
            field: $subDistributionField
            startDate: $subDistributionStartDate
            endDate: $subDistributionEndDate
            dateAttribute: $subDistributionDateAttribute
            operation: $subDistributionOperation
            limit: $subDistributionLimit
            order: $subDistributionOrder
            types: $subDistributionTypes
            filters: $subDistributionFilters
            search: $subDistributionSearch
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
              ... on Label {
                color
              }
              ... on MarkingDefinition {
                x_opencti_color
              }
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
      }
    }
  }
`;

// ---------------------------------------------------------------------------
// Inner component (Suspense boundary consumer)
// ---------------------------------------------------------------------------

interface StixRelationshipsMultiHorizontalBarsComponentProps {
  queryRef: PreloadedQuery<StixRelationshipsMultiHorizontalBarsWithRelationshipsDistributionQuery>
    | PreloadedQuery<StixRelationshipsMultiHorizontalBarsWithEntitiesDistributionQuery>;
  queryToCall:
    | typeof stixRelationshipsMultiHorizontalBarsWithRelationshipsDistributionQuery
    | typeof stixRelationshipsMultiHorizontalBarsWithEntitiesDistributionQuery;
  parameters: WidgetParameters;
  subSelection: Partial<WidgetDataSelection>;
  finalSubDistributionField: string;
  finalField: string;
  onMounted: (chart: ApexCharts) => void;
}

const StixRelationshipsMultiHorizontalBarsComponent: FunctionComponent<StixRelationshipsMultiHorizontalBarsComponentProps> = ({
  queryRef,
  parameters = {},
  queryToCall,
  subSelection,
  finalSubDistributionField,
  finalField,
  onMounted,
}) => {
  const { stixRelationshipsDistribution } = usePreloadedQuery(
    // Cast needed: both queries share the same response shape for this field.
    queryToCall as typeof stixRelationshipsMultiHorizontalBarsWithRelationshipsDistributionQuery,
    queryRef as PreloadedQuery<StixRelationshipsMultiHorizontalBarsWithRelationshipsDistributionQuery>,
  );

  if (!stixRelationshipsDistribution || stixRelationshipsDistribution.length === 0) {
    return <WidgetNoData />;
  }

  const { chartData, redirectionUtils, categories } = useStixRelationshipsMultiHorizontalBars(
    subSelection,
    stixRelationshipsDistribution,
    finalSubDistributionField,
    finalField,
  );

  return (
    <WidgetHorizontalBars
      series={chartData}
      distributed={parameters.distributed ?? undefined}
      redirectionUtils={redirectionUtils}
      stacked
      total
      legend
      categories={categories}
      onMounted={onMounted}
    />
  );
};

// ---------------------------------------------------------------------------
// Outer component (query loader + layout)
// ---------------------------------------------------------------------------

interface StixRelationshipsMultiHorizontalBarsProps {
  title?: string;
  variant?: string;
  height?: CSSProperties['height'];
  field?: string;
  startDate?: string | null;
  endDate?: string | null;
  dataSelection: WidgetDataSelection[];
  parameters?: WidgetParameters;
  popover?: React.ReactNode;
  host?: WidgetHost;
  config?: DashboardConfig;
  refreshRate?: number | null;
}

const StixRelationshipsMultiHorizontalBars: FunctionComponent<StixRelationshipsMultiHorizontalBarsProps> = ({
  title,
  variant,
  height,
  field,
  startDate,
  endDate,
  dataSelection,
  parameters = {},
  popover,
  host,
}) => {
  const { t_i18n } = useFormatter();
  const [chart, setChart] = useState<ApexCharts>();
  const { resolvedDataSelection, isMissingHostEntity, isMissingSavedFilters, isPreviewMode } = useDashboardViz({
    perspective: 'relationships',
    dataSelection,
    host,
  });

  let selection: Partial<WidgetDataSelection> = {};
  let filtersAndOptions;
  let subDistributionFiltersAndOptions;
  let subSelection: Partial<WidgetDataSelection> = {};
  let subDistributionTypes: string[] | null = null;
  if (resolvedDataSelection) {
    selection = resolvedDataSelection[0];
    filtersAndOptions = buildFiltersAndOptionsForWidgets(selection.filters, { isKnowledgeRelationshipWidget: true });
    if (resolvedDataSelection.length > 1) {
      subSelection = resolvedDataSelection[1];
      subDistributionFiltersAndOptions = buildFiltersAndOptionsForWidgets(subSelection.filters);
      if (subSelection.perspective === 'entities') {
        subDistributionTypes = ['Stix-Core-Object'];
      }
    }
  }

  const finalField = selection.attribute || field || 'entity_type';
  const finalSubDistributionField = subSelection.attribute || field || 'entity_type';

  // Base variables shared by both query variants.
  let variables:
    | StixRelationshipsMultiHorizontalBarsWithRelationshipsDistributionQuery['variables']
    | StixRelationshipsMultiHorizontalBarsWithEntitiesDistributionQuery['variables'] = {
      field: finalField,
      operation: 'count',
      startDate,
      endDate,
      dateAttribute: selection.date_attribute ?? 'created_at',
      limit: selection.number ?? 10,
      filters: normalizeFilterGroupForBackend(filtersAndOptions?.filters),
      isTo: selection.isTo,
      dynamicFrom: normalizeFilterGroupForBackend(selection.dynamicFrom),
      dynamicTo: normalizeFilterGroupForBackend(selection.dynamicTo),
      subDistributionField: finalSubDistributionField,
      subDistributionOperation: 'count',
    };

  if (subSelection.perspective === 'entities') {
    variables = {
      ...variables,
      subDistributionStartDate: startDate,
      subDistributionEndDate: endDate,
      subDistributionDateAttribute:
        subSelection.date_attribute && subSelection.date_attribute.length > 0
          ? subSelection.date_attribute
          : 'created_at',
      subDistributionLimit: subSelection.number ?? 15,
      subDistributionTypes,
      subDistributionFilters: normalizeFilterGroupForBackend(subDistributionFiltersAndOptions?.filters),
    } as StixRelationshipsMultiHorizontalBarsWithEntitiesDistributionQuery['variables'];
  } else {
    variables = {
      ...variables,
      subDistributionStartDate: startDate,
      subDistributionEndDate: endDate,
      subDistributionDateAttribute:
        subSelection.date_attribute && subSelection.date_attribute.length > 0
          ? subSelection.date_attribute
          : 'created_at',
      subDistributionIsTo: subSelection.isTo,
      subDistributionLimit: subSelection.number ?? 15,
      subDistributionFilters: normalizeFilterGroupForBackend(subDistributionFiltersAndOptions?.filters),
    } as StixRelationshipsMultiHorizontalBarsWithRelationshipsDistributionQuery['variables'];
  }

  const queryToCall = subSelection.perspective === 'entities'
    ? stixRelationshipsMultiHorizontalBarsWithEntitiesDistributionQuery
    : stixRelationshipsMultiHorizontalBarsWithRelationshipsDistributionQuery;
  const [queryRef, loadQuery] = useQueryLoadingWithLoadQuery<
    StixRelationshipsMultiHorizontalBarsWithRelationshipsDistributionQuery
    | StixRelationshipsMultiHorizontalBarsWithEntitiesDistributionQuery
  >(queryToCall, variables);
  const [, startTransition] = useTransition();

  const refreshToken = useDashboardRefreshToken();
  const prevRefreshTokenRef = useRef(refreshToken);
  useEffect(() => {
    if (prevRefreshTokenRef.current === refreshToken) return;
    prevRefreshTokenRef.current = refreshToken;
    startTransition(() => {
      loadQuery(variables, { fetchPolicy: 'store-and-network' });
    });
  }, [refreshToken, loadQuery, startTransition, variables]);

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
        <StixRelationshipsMultiHorizontalBarsComponent
          queryRef={queryRef}
          parameters={parameters}
          finalField={finalField}
          queryToCall={queryToCall}
          subSelection={subSelection}
          finalSubDistributionField={finalSubDistributionField}
          onMounted={setChart}
        />
      </Suspense>
    );
  };

  return (
    <WidgetContainer
      padding="small"
      height={height}
      title={parameters.title ?? title ?? t_i18n('Distribution of entities')}
      variant={variant}
      chart={chart}
      action={popover}
      showPreviewTag={isPreviewMode}
    >
      {renderContent()}
    </WidgetContainer>
  );
};

export default StixRelationshipsMultiHorizontalBars;
