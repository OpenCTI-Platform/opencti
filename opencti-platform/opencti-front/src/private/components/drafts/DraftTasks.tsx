import React, { FunctionComponent } from 'react';
import { graphql } from 'react-relay';
import { DraftTasksQuery, DraftTasksQuery$variables } from '@components/drafts/__generated__/DraftTasksQuery.graphql';
import { DraftTasksLines_data$data } from '@components/drafts/__generated__/DraftTasksLines_data.graphql';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { emptyFilterGroup } from '../../../utils/filters/filtersUtils';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import { UsePreloadedPaginationFragment } from '../../../utils/hooks/usePreloadedPaginationFragment';
import { DataTableProps, DataTableVariant } from '../../../components/dataGrid/dataTableTypes';
import DataTable from '../../../components/dataGrid/DataTable';
import { defaultRender } from '../../../components/dataGrid/dataTableUtils';

export const draftTaskLineFragment = graphql`
    fragment DraftTasksLine_task on BackgroundTask {
        id
        initiator {
          id
          name
          representative {
            main
          }
        }
        type
        actions {
            type
            context {
                field
                type
                values
            }
        }
        created_at
        last_execution_date
        completed
        task_expected_number
        task_processed_number
    }
`;

const draftTasksLinesFragment = graphql`
    fragment DraftTasksLines_data on Query
    @argumentDefinitions(
        count: { type: "Int", defaultValue: 500 }
        cursor: { type: "ID" }
        orderBy: { type: "BackgroundTasksOrdering" }
        orderMode: { type: "OrderingMode" }
        search: { type: "String" }
        filters: { type: "FilterGroup" }
    )
    @refetchable(queryName: "DraftTasksRefetchQuery") {
        backgroundTasks(
            first: $count,
            after: $cursor,
            orderBy: $orderBy,
            orderMode: $orderMode,
            search: $search,
            filters: $filters,
        )
        @connection(key: "Pagination_global_backgroundTasks") {
            edges {
                node {
                    id
                    ...DraftTasksLine_task
                }
            }
            pageInfo {
                globalCount
            }
        }
    }
`;

export const draftTasksQuery = graphql`
    query DraftTasksQuery(
        $count: Int,
        $cursor: ID,
        $orderBy: BackgroundTasksOrdering,
        $orderMode: OrderingMode,
        $search: String,
        $filters: FilterGroup,
    ) {
        ...DraftTasksLines_data
        @arguments(
            count: $count
            cursor: $cursor
            orderBy: $orderBy
            orderMode: $orderMode
            search: $search
            filters: $filters
        )
    }
`;

const LOCAL_STORAGE_KEY = 'draft_tasks';

interface DraftTasksProps {
  draftId: string;
}

const DraftTasks : FunctionComponent<DraftTasksProps> = ({ draftId }) => {
  const initialValues = {
    filters: {
      ...emptyFilterGroup,
    },
    searchTerm: '',
    sortBy: 'created_at',
    orderAsc: false,
  };

  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<DraftTasksQuery$variables>(LOCAL_STORAGE_KEY, initialValues, true);
  const { filters } = viewStorage;
  const currentDraftFilter = { key: 'draft_context', values: [draftId], operator: 'eq', mode: 'or' };
  const finalFilters = { ...filters, filters: [...(filters?.filters ?? []), currentDraftFilter] };
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: finalFilters,
  } as unknown as DraftTasksQuery$variables;

  const queryRef = useQueryLoading<DraftTasksQuery>(draftTasksQuery, queryPaginationOptions);

  const preloadedPaginationProps = {
    linesQuery: draftTasksQuery,
    linesFragment: draftTasksLinesFragment,
    queryRef,
    nodePath: ['backgroundTasks', 'pageInfo', 'globalCount'],
    setNumberOfElements: helpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<DraftTasksQuery>;

  const dataColumns: DataTableProps['dataColumns'] = {
    initiator: {
      label: 'Initiator',
      percentWidth: 25,
      isSortable: true,
      render: ({ initiator }) => defaultRender(initiator.representative.main),
    },
    created_at: {
      percentWidth: 25,
      isSortable: true,
    },
    last_execution_date: {
      label: 'Last execution',
      percentWidth: 25,
      isSortable: true,
      render: ({ last_execution_date }, h) => defaultRender(h.fd(last_execution_date)),
    },
    completed: {
      label: 'Completed',
      percentWidth: 25,
      isSortable: false,
      render: ({ completed }) => defaultRender(completed),
    },
  };

  return (
    <span data-testid="draft-tasks-page">
      {queryRef && (
      <DataTable
        dataColumns={dataColumns}
        resolvePath={(data: DraftTasksLines_data$data) => data.backgroundTasks?.edges?.map((n) => n?.node)}
        storageKey={LOCAL_STORAGE_KEY}
        initialValues={initialValues}
        preloadedPaginationProps={preloadedPaginationProps}
        variant={DataTableVariant.inline}
        disableNavigation
        disableLineSelection
        lineFragment={draftTaskLineFragment}
      />
      )}
    </span>
  );
};

export default DraftTasks;
