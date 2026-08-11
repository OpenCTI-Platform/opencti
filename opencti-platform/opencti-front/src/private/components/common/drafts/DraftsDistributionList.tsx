import React, { ReactNode } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import useGranted, { SETTINGS_SETACCESSES } from '../../../../utils/hooks/useGranted';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetDistributionList from '../../../../components/dashboard/WidgetDistributionList';
import { getMainRepresentative, isFieldForIdentifier } from '../../../../utils/defaultRepresentatives';
import { computeWidgetFiltersForSelection } from '../../../../components/dashboard/dashboardVizUtils';
import type { DashboardConfig } from '../../../../components/dashboard/dashboard-types';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import WidgetRenderContent from '../../../../components/dashboard/WidgetRenderContent';
import type { Widget, WidgetDataSelection, WidgetHost, WidgetParameters } from '../../../../utils/widget/widget';
import { DraftsDistributionListQuery } from './__generated__/DraftsDistributionListQuery.graphql';

const draftsDistributionListQuery = graphql`
  query DraftsDistributionListQuery(
    $field: String!
    $startDate: DateTime
    $endDate: DateTime
    $dateAttribute: String
    $operation: StatsOperation!
    $limit: Int
    $order: String
    $filters: FilterGroup
    $search: String
  ) {
    draftWorkspacesDistribution(
      field: $field
      startDate: $startDate
      endDate: $endDate
      dateAttribute: $dateAttribute
      operation: $operation
      limit: $limit
      order: $order
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
        ... on StixObject {
          representative {
            main
          }
        }
        ... on Creator {
          name
        }
        ... on Group {
          name
        }
      }
    }
  }
`;

interface DraftsDistributionListComponentProps {
  queryRef: PreloadedQuery<DraftsDistributionListQuery>;
  dataSelection: Widget['dataSelection'];
  hasSetAccess: boolean;
}

const DraftsDistributionListComponent = ({
  queryRef,
  dataSelection,
  hasSetAccess,
}: DraftsDistributionListComponentProps) => {
  const { t_i18n } = useFormatter();
  const data = usePreloadedQuery(draftsDistributionListQuery, queryRef);
  const selection = dataSelection[0];
  const raw = data?.draftWorkspacesDistribution ?? [];
  if (raw.length === 0) {
    return <WidgetNoData />;
  }
  const formatted = raw.map((n) => {
    let label = n?.label;
    if (isFieldForIdentifier(selection.attribute ?? undefined)) {
      label = getMainRepresentative(n?.entity) || n?.label;
    } else if (
      selection.attribute === 'entity_type'
      && n?.label
      && t_i18n(`entity_${n.label}`) !== `entity_${n.label}`
    ) {
      label = t_i18n(`entity_${n.label}`);
    }
    return {
      label,
      value: n?.value,
      id: isFieldForIdentifier(selection.attribute ?? undefined) ? n?.entity?.id : null,
      type: n?.entity?.entity_type ?? n?.label,
    };
  });

  return (
    <WidgetDistributionList
      data={formatted}
      hasSettingAccess={hasSetAccess}
    />
  );
};

interface DraftsDistributionListProps {
  dataSelection: Widget['dataSelection'];
  parameters?: WidgetParameters;
  popover?: ReactNode;
  variant?: string;
  height?: number;
  host?: WidgetHost;
  config: DashboardConfig;
  refreshRate?: number | null;
}

const buildQueryVariables = (resolvedDataSelection: WidgetDataSelection[], config: DashboardConfig): DraftsDistributionListQuery['variables'] => {
  const selection = resolvedDataSelection[0];
  const { dateAttribute, startDate, endDate, filters } = computeWidgetFiltersForSelection(selection, config);
  return {
    field: selection.attribute ?? 'entity_type',
    operation: 'count' as DraftsDistributionListQuery['variables']['operation'],
    startDate,
    endDate,
    dateAttribute,
    filters,
    limit: selection.number ?? 10,
  };
};

const DraftsDistributionList = ({
  variant,
  height,
  dataSelection,
  parameters = {},
  popover,
  config,
  refreshRate = null,
  host,
}: DraftsDistributionListProps) => {
  const { t_i18n } = useFormatter();
  const hasSetAccess = useGranted([SETTINGS_SETACCESSES]);
  const { resolvedDataSelection, isMissingHostEntity, isMissingSavedFilters, isPreviewMode, queryRef } = useDashboardViz<DraftsDistributionListQuery>({
    perspective: 'entities',
    dataSelection,
    host,
    refreshRate,
    query: draftsDistributionListQuery,
    config,
    buildQueryVariables,
  });

  return (
    <WidgetContainer
      height={height}
      title={parameters.title ?? t_i18n('Distribution of draft workspaces')}
      variant={variant}
      action={popover}
      showPreviewTag={isPreviewMode}
    >
      <div style={{ height: '100%' }}>
        <WidgetRenderContent
          isMissingHostEntity={isMissingHostEntity}
          isMissingSavedFilters={isMissingSavedFilters}
          queryRef={queryRef}
          host={host}
        >
          <DraftsDistributionListComponent
            queryRef={queryRef!}
            dataSelection={resolvedDataSelection}
            hasSetAccess={hasSetAccess}
          />
        </WidgetRenderContent>
      </div>
    </WidgetContainer>
  );
};

export default DraftsDistributionList;
