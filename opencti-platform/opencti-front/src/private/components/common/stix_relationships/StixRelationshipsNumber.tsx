import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import { dayAgo } from '../../../../utils/Time';
import { buildFiltersAndOptionsForWidgets, normalizeFilterGroupForBackend } from '../../../../utils/filters/filtersUtils';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import useEntityTranslation from '../../../../utils/hooks/useEntityTranslation';
import WidgetNumber from '../../../../components/dashboard/WidgetNumber';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import WidgetRenderContent from '../../../../components/dashboard/WidgetRenderContent';
import { StixRelationshipsNumberNumberSeriesQuery } from '@components/common/stix_relationships/__generated__/StixRelationshipsNumberNumberSeriesQuery.graphql';
import { WidgetDataSelection, WidgetHost, WidgetParameters } from '../../../../utils/widget/widget';
import { ReactNode } from 'react';
import { DashboardConfig } from '../../../../components/dashboard/dashboard-types';

const stixRelationshipsNumberNumberQuery = graphql`
    query StixRelationshipsNumberNumberSeriesQuery(
        $dateAttribute: String
        $noDirection: Boolean
        $endDate: DateTime
        $onlyInferred: Boolean
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
        stixRelationshipsNumber(
            dateAttribute: $dateAttribute
            noDirection: $noDirection
            endDate: $endDate
            onlyInferred: $onlyInferred
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
            total
            count
        }
    }
`;

interface StixRelationshipsNumberComponentProps {
  queryRef: PreloadedQuery<StixRelationshipsNumberNumberSeriesQuery>;
  dataSelection: WidgetDataSelection[];
  parameters?: WidgetParameters;
  entityType?: string;
}

const StixRelationshipsNumberComponent = ({
  queryRef,
  parameters,
  entityType,
}: StixRelationshipsNumberComponentProps) => {
  const { t_i18n } = useFormatter();
  const { translateEntityType } = useEntityTranslation();
  const data = usePreloadedQuery(
    stixRelationshipsNumberNumberQuery,
    queryRef,
  );

  if (!data?.stixRelationshipsNumber) {
    return <WidgetNoData />;
  }
  const { total, count } = data.stixRelationshipsNumber;
  const title = parameters?.title ?? t_i18n('Entities number');
  const translatedTitle = translateEntityType(title);

  return (
    <WidgetNumber
      entityType={entityType}
      label={translatedTitle}
      value={total}
      diffLabel={t_i18n('24 hours')}
      diffValue={total - count}
    />
  );
};

const buildQueryVariables = (
  resolvedDataSelection: WidgetDataSelection[],
): StixRelationshipsNumberNumberSeriesQuery['variables'] => {
  const selection = resolvedDataSelection[0];
  const dateAttribute
    = selection.date_attribute?.length
      ? selection.date_attribute
      : 'created_at';
  const { filters } = buildFiltersAndOptionsForWidgets(
    selection.filters,
    {
      dateAttribute,
      isKnowledgeRelationshipWidget: true,
    },
  );

  return {
    filters: normalizeFilterGroupForBackend(filters),
    dateAttribute,
    endDate: dayAgo(),
    dynamicFrom: normalizeFilterGroupForBackend(selection.dynamicFrom),
    dynamicTo: normalizeFilterGroupForBackend(selection.dynamicTo),
  };
};

interface StixRelationshipsNumberProps {
  variant?: string;
  height?: number;
  dataSelection: WidgetDataSelection[];
  parameters?: WidgetParameters;
  popover?: ReactNode;
  host?: WidgetHost;
  config: DashboardConfig;
  refreshRate?: number | null;
  entityType?: string;
}

const StixRelationshipsNumber = ({
  dataSelection,
  parameters = {},
  entityType,
  popover,
  variant,
  height,
  host,
  config,
  refreshRate = null,
}: StixRelationshipsNumberProps) => {
  const { t_i18n } = useFormatter();

  const { resolvedDataSelection, isMissingHostEntity, isMissingSavedFilters, isPreviewMode, queryRef } = useDashboardViz<StixRelationshipsNumberNumberSeriesQuery>({
    perspective: 'relationships',
    dataSelection,
    host,
    refreshRate,
    query: stixRelationshipsNumberNumberQuery,
    config,
    buildQueryVariables,
  });

  return (
    <WidgetContainer
      padding="medium"
      height={height}
      title={t_i18n('Relationships number')}
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
        <StixRelationshipsNumberComponent
          queryRef={queryRef!}
          dataSelection={resolvedDataSelection}
          parameters={parameters}
          entityType={entityType}
        />
      </WidgetRenderContent>
    </WidgetContainer>
  );
};

export default StixRelationshipsNumber;
