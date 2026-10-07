import React, { useState } from 'react';
import { graphql } from 'react-relay';
import { Route, Routes } from 'react-router';
import { Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { HuntRuns_RunFragment$data } from './__generated__/HuntRuns_RunFragment.graphql';
import { HuntRuns_RunsFragment$data } from './__generated__/HuntRuns_RunsFragment.graphql';
import { HuntRunsListQuery, HuntRunsListQuery$variables } from './__generated__/HuntRunsListQuery.graphql';
import HuntRunStart from './HuntRunStart';
import HuntRunDrawer from './HuntRunDrawer';
import { HuntRunStatusChip, HuntVerdictChip } from '../HuntChips';
import { formatHuntRunDuration, HUNT_RUN_ENTITY_TYPE, huntMessageText, huntRunPartialResultsSentence, huntRunTriggerLabel } from '../hunt-utils';
import { PATH_HUNT } from '../../common/routes/paths';
import { useFormatter } from '../../../../components/i18n';
import DataTable from '../../../../components/dataGrid/DataTable';
import { defaultRender } from '../../../../components/dataGrid/dataTableUtils';
import { DataTableProps } from '../../../../components/dataGrid/dataTableTypes';
import { emptyFilterGroup } from '../../../../utils/filters/filtersUtils';
import type { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { UsePreloadedPaginationFragment } from '../../../../utils/hooks/usePreloadedPaginationFragment';

export const huntRunsLineFragment = graphql`
  fragment HuntRuns_RunFragment on HuntRun {
    id
    entity_type
    hunt_id
    hunt_run_status
    hunt_run_trigger
    hunt_run_mode
    connector_name
    queue_reason {
      template
      values {
        name
        value
      }
    }
    securityPlatform {
      id
      name
    }
    hits_count
    results_truncated
    verdict
    verdict_source
    created_at
    started_at
    completed_at
    cost_ms
  }
`;

export const huntRunsLinesFragment = graphql`
  fragment HuntRuns_RunsFragment on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "HuntRunsOrdering", defaultValue: created_at }
    orderMode: { type: "OrderingMode", defaultValue: desc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "HuntRunsRefetchQuery") {
    huntRuns(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_huntRuns") {
      edges {
        node {
          id
          ...HuntRuns_RunFragment
        }
      }
      pageInfo {
        endCursor
        hasNextPage
        globalCount
      }
    }
  }
`;

export const huntRunsListQuery = graphql`
  query HuntRunsListQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: HuntRunsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...HuntRuns_RunsFragment
    @arguments(
      search: $search
      count: $count
      cursor: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    )
  }
`;

const RUN_FILTER_KEYS = ['hunt_run_status', 'hunt_run_trigger', 'hunt_run_mode', 'verdict', 'verdict_source', 'hits_count', 'completed_at'];

/** Runs are scoped to their hunt with a context filter the user cannot remove. */
export const huntRunsContextFilters = (huntId: string, filters: FilterGroup | undefined): FilterGroup => ({
  mode: 'and',
  filters: [
    { key: 'entity_type', values: [HUNT_RUN_ENTITY_TYPE], operator: 'eq', mode: 'or' },
    { key: 'hunt_id', values: [huntId], operator: 'eq', mode: 'or' },
  ],
  filterGroups: filters && Object.keys(filters).length > 0 ? [filters] : [],
});

interface HuntRunsProps {
  hunt: {
    id: string;
    hunt_status: string;
    hunt_type: string;
    time_window_hours: number;
    hunt_max_results?: number | null;
    scopePlatforms?: ReadonlyArray<{ id: string; name: string }> | null;
  };
  // The edit right of the hunt page: running the hunt or acting on its runs changes it
  canEdit: boolean;
}

const HuntRuns = ({ hunt, canEdit }: HuntRunsProps) => {
  const { t_i18n, n } = useFormatter();
  const [tableElement, setTableElement] = useState<HTMLDivElement | null>(null);
  const storageKey = `hunt-${hunt.id}-runs`;
  const initialValues = {
    filters: emptyFilterGroup,
    searchTerm: '',
    sortBy: 'created_at',
    orderAsc: false,
    openExports: false,
  };
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<HuntRunsListQuery$variables>(storageKey, initialValues);
  const contextFilters = huntRunsContextFilters(hunt.id, viewStorage.filters);
  const queryPaginationOptions = { ...paginationOptions, filters: contextFilters } as unknown as HuntRunsListQuery$variables;
  const queryRef = useQueryLoading<HuntRunsListQuery>(huntRunsListQuery, queryPaginationOptions);

  const dateRender = (value: string | null | undefined, fd: (date: string | null | undefined) => string) => defaultRender(value ? fd(value) : '-');
  const dataColumns: DataTableProps['dataColumns'] = {
    created_at: {
      id: 'created_at',
      label: 'Creation date',
      percentWidth: 14,
      isSortable: true,
      render: ({ created_at }: HuntRuns_RunFragment$data, { fd }: { fd: (date: string | null | undefined) => string }) => dateRender(created_at, fd),
    },
    hunt_run_status: {
      id: 'hunt_run_status',
      label: 'Status',
      percentWidth: 10,
      isSortable: true,
      render: ({ hunt_run_status, queue_reason }: HuntRuns_RunFragment$data) => (queue_reason ? (
        <Tooltip>
          <TooltipTrigger asChild>
            <span tabIndex={0} aria-label={huntMessageText(queue_reason, t_i18n)} data-testid="hunt-run-queue-reason">
              <HuntRunStatusChip value={hunt_run_status} />
            </span>
          </TooltipTrigger>
          <TooltipContent>{huntMessageText(queue_reason, t_i18n)}</TooltipContent>
        </Tooltip>
      ) : <HuntRunStatusChip value={hunt_run_status} />),
    },
    hunt_run_trigger: {
      id: 'hunt_run_trigger',
      label: 'Trigger',
      percentWidth: 10,
      isSortable: true,
      render: ({ hunt_run_trigger }: HuntRuns_RunFragment$data) => defaultRender(t_i18n(huntRunTriggerLabel(hunt_run_trigger))),
    },
    securityPlatform: {
      id: 'securityPlatform',
      label: 'Platform',
      percentWidth: 16,
      isSortable: false,
      render: ({ securityPlatform, connector_name }: HuntRuns_RunFragment$data) => defaultRender(securityPlatform?.name ?? connector_name ?? t_i18n('Internet')),
    },
    hits_count: {
      id: 'hits_count',
      label: 'Hits',
      percentWidth: 8,
      isSortable: true,
      render: ({ hits_count, results_truncated, securityPlatform, connector_name }: HuntRuns_RunFragment$data) => {
        if (hits_count === null || hits_count === undefined) {
          return defaultRender('-');
        }
        if (!results_truncated) {
          return defaultRender(n(hits_count));
        }
        const platform = securityPlatform?.name ?? connector_name ?? t_i18n('Internet');
        return (
          <Tooltip>
            <TooltipTrigger asChild>
              <span tabIndex={0} data-testid="hunt-run-hits-lower-bound">{t_i18n('At least {count}', { values: { count: n(hits_count) } })}</span>
            </TooltipTrigger>
            <TooltipContent>{huntRunPartialResultsSentence({ hits_count, maxResults: hunt.hunt_max_results }, platform, t_i18n, n)}</TooltipContent>
          </Tooltip>
        );
      },
    },
    verdict: {
      id: 'verdict',
      label: 'Verdict',
      percentWidth: 12,
      isSortable: true,
      render: ({ verdict, hunt_run_mode }: HuntRuns_RunFragment$data) => (hunt_run_mode === 'preview' ? defaultRender(t_i18n('Preview')) : <HuntVerdictChip value={verdict} />),
    },
    completed_at: {
      id: 'completed_at',
      label: 'Completion date',
      percentWidth: 16,
      isSortable: true,
      render: ({ completed_at }: HuntRuns_RunFragment$data, { fd }: { fd: (date: string | null | undefined) => string }) => dateRender(completed_at, fd),
    },
    cost_ms: {
      id: 'cost_ms',
      label: 'Duration',
      percentWidth: 14,
      isSortable: false,
      render: ({ cost_ms }: HuntRuns_RunFragment$data) => defaultRender(formatHuntRunDuration(cost_ms) ?? '-'),
    },
  };

  const preloadedPaginationProps = {
    linesQuery: huntRunsListQuery,
    linesFragment: huntRunsLinesFragment,
    queryRef,
    nodePath: ['huntRuns', 'pageInfo', 'globalCount'],
    setNumberOfElements: helpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<HuntRunsListQuery>;

  return (
    <div data-testid="hunt-runs-page">
      <div ref={setTableElement} style={{ height: 'calc(100vh - 280px)', minHeight: 360 }}>
        {queryRef && tableElement && (
          <DataTable
            rootRef={tableElement}
            storageKey={storageKey}
            initialValues={initialValues}
            preloadedPaginationProps={preloadedPaginationProps}
            resolvePath={(data: HuntRuns_RunsFragment$data) => data.huntRuns?.edges?.map((edge) => edge?.node)}
            dataColumns={dataColumns}
            lineFragment={huntRunsLineFragment}
            contextFilters={contextFilters}
            availableFilterKeys={RUN_FILTER_KEYS}
            availableEntityTypes={[HUNT_RUN_ENTITY_TYPE]}
            entityTypes={[HUNT_RUN_ENTITY_TYPE]}
            getComputeLink={(run: { id: string }) => `${PATH_HUNT(hunt.id)}/runs/${run.id}`}
            disableLineSelection
            disableToolBar
            removeSelectAll
            emptyStateMessage={canEdit
              ? t_i18n('No run yet: click Run now to run the hunt over its time window, or Activate it to run on its schedule.')
              : t_i18n('No run yet. Runs appear here once a user who can edit the hunt runs it or activates it.')}
            createButton={canEdit ? <HuntRunStart hunt={hunt} paginationOptions={queryPaginationOptions} /> : undefined}
          />
        )}
      </div>
      <Routes>
        <Route path=":runId" element={<HuntRunDrawer huntId={hunt.id} canEdit={canEdit} paginationOptions={queryPaginationOptions} />} />
      </Routes>
    </div>
  );
};

export default HuntRuns;
