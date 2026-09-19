import React, { CSSProperties, ReactNode, useRef } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import { computeWidgetFiltersForSelection } from '../../../../components/dashboard/dashboardVizUtils';
import type { DashboardConfig } from '../../../../components/dashboard/dashboard-types';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetListCoreObjects from '../../../../components/dashboard/WidgetListCoreObjects';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import WidgetRenderContent from '../../../../components/dashboard/WidgetRenderContent';
import type { WidgetColumn, WidgetDataSelection, WidgetHost, WidgetParameters } from '../../../../utils/widget/widget';
import { DraftsListQuery } from './__generated__/DraftsListQuery.graphql';

const defaultDraftColumns: WidgetColumn[] = [
  { attribute: 'name', label: 'Name' },
  { attribute: 'draft_status', label: 'Processing status' },
  { attribute: 'workflowInstance', label: 'Workflow status' },
  { attribute: 'creators', label: 'Creators' },
  { attribute: 'createdBy' },
  { attribute: 'objectAssignee' },
  { attribute: 'objectParticipant' },
  { attribute: 'created_at', label: 'Creation date' },
];

export const draftsListQuery = graphql`
  query DraftsListQuery(
    $first: Int
    $orderBy: DraftWorkspacesOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    draftWorkspaces(
      first: $first
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) {
      edges {
        node {
          id
          entity_type
          name
          draft_status
          created_at
          creators {
            id
            name
          }
          createdBy {
            ... on Identity {
              id
              name
              entity_type
            }
          }
          objectAssignee {
            entity_type
            id
            name
          }
          objectParticipant {
            entity_type
            id
            name
          }
          workflowInstance {
            currentStatus {
              id
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
`;

// ---------------------------------------------------------------------------
// Query variables builder
// ---------------------------------------------------------------------------

const buildQueryVariables = (
  resolvedDataSelection: WidgetDataSelection[],
  config: DashboardConfig,
): DraftsListQuery['variables'] => {
  const selection = resolvedDataSelection[0];
  const orderBy = (selection.sort_by && selection.sort_by.length > 0
    ? selection.sort_by
    : 'created_at') as DraftsListQuery['variables']['orderBy'];
  const { filters } = computeWidgetFiltersForSelection(selection, config);
  return {
    first: selection.number ?? 10,
    orderBy,
    orderMode: (selection.sort_mode ?? 'desc') as DraftsListQuery['variables']['orderMode'],
    filters,
  };
};

// ---------------------------------------------------------------------------
// Inner component (Suspense boundary consumer)
// ---------------------------------------------------------------------------

interface DraftsListComponentProps {
  rootRef: React.RefObject<HTMLDivElement | null>;
  queryRef: PreloadedQuery<DraftsListQuery>;
  dataSelection: WidgetDataSelection[];
  widgetId: string;
}

const DraftsListComponent = ({
  rootRef,
  queryRef,
  dataSelection,
  widgetId,
}: DraftsListComponentProps) => {
  const data = usePreloadedQuery(draftsListQuery, queryRef);
  const selection = dataSelection[0];
  const columns: WidgetColumn[] = selection.columns ? [...selection.columns] : defaultDraftColumns;
  const edges = data?.draftWorkspaces?.edges ?? [];

  if (edges.length === 0) {
    return <WidgetNoData />;
  }

  return (
    <WidgetListCoreObjects
      data={[...edges]}
      rootRef={rootRef.current ?? undefined}
      widgetId={widgetId}
      pageSize={selection.number ?? 10}
      columns={columns}
    />
  );
};

// ---------------------------------------------------------------------------
// Outer component (query loader + layout)
// ---------------------------------------------------------------------------

interface DraftsListProps {
  title?: string;
  variant?: string;
  height?: CSSProperties['height'];
  config: DashboardConfig;
  refreshRate?: number | null;
  dataSelection: WidgetDataSelection[];
  widgetId: string;
  parameters?: WidgetParameters;
  popover?: ReactNode;
  host?: WidgetHost;
}

const DraftsList = ({
  title,
  variant,
  height,
  config,
  refreshRate = null,
  dataSelection,
  widgetId,
  parameters = {},
  popover,
  host,
}: DraftsListProps) => {
  const { t_i18n } = useFormatter();
  const rootRef = useRef<HTMLDivElement>(null);

  const { resolvedDataSelection, isMissingHostEntity, isMissingSavedFilters, isPreviewMode, queryRef } = useDashboardViz<DraftsListQuery>({
    perspective: 'entities',
    dataSelection,
    host,
    refreshRate,
    query: draftsListQuery,
    config,
    buildQueryVariables,
  });

  return (
    <WidgetContainer
      padding="horizontal"
      height={height}
      title={parameters.title ?? title ?? t_i18n('Draft workspaces list')}
      variant={variant}
      action={popover}
      showPreviewTag={isPreviewMode}
    >
      <div ref={rootRef} style={{ height: '100%' }}>
        <WidgetRenderContent
          isMissingHostEntity={isMissingHostEntity}
          isMissingSavedFilters={isMissingSavedFilters}
          queryRef={queryRef}
          host={host}
        >
          <DraftsListComponent
            queryRef={queryRef!}
            rootRef={rootRef}
            dataSelection={resolvedDataSelection}
            widgetId={widgetId}
          />
        </WidgetRenderContent>
      </div>
    </WidgetContainer>
  );
};

export default DraftsList;
