import React, { FunctionComponent } from 'react';
import { graphql } from 'react-relay';
import { DraftWorksQuery, DraftWorksQuery$variables } from '@components/drafts/__generated__/DraftWorksQuery.graphql';
import { DraftWorksLines_data$data } from '@components/drafts/__generated__/DraftWorksLines_data.graphql';
import { CsvMapperLine_csvMapper$data } from '@components/data/csvMapper/__generated__/CsvMapperLine_csvMapper.graphql';
import { DraftWorksLine_work$data } from '@components/drafts/__generated__/DraftWorksLine_work.graphql';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { emptyFilterGroup } from '../../../utils/filters/filtersUtils';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import { UsePreloadedPaginationFragment } from '../../../utils/hooks/usePreloadedPaginationFragment';
import { DataTableProps, DataTableVariant } from '../../../components/dataGrid/dataTableTypes';
import DataTable from '../../../components/dataGrid/DataTable';
import { defaultRender } from '../../../components/dataGrid/dataTableUtils';

export const draftWorkLineFragment = graphql`
    fragment DraftWorksLine_work on Work {
        id
        name
        connector {
            id
            name
        }
        status
        timestamp
        received_time
        completed_time
    }
`;

const draftWorksLinesFragment = graphql`
    fragment DraftWorksLines_data on Query
    @argumentDefinitions(
        count: { type: "Int", defaultValue: 500 }
        cursor: { type: "ID" }
        orderBy: { type: "WorksOrdering" }
        orderMode: { type: "OrderingMode" }
        search: { type: "String" }
        filters: { type: "FilterGroup" }
    )
    @refetchable(queryName: "DraftWorksRefetchQuery") {
        works(
            first: $count,
            after: $cursor,
            orderBy: $orderBy,
            orderMode: $orderMode,
            search: $search,
            filters: $filters,
        )
        @connection(key: "Pagination_global_works") {
            edges {
                node {
                    ...DraftWorksLine_work
                }
            }
            pageInfo {
                globalCount
            }
        }
    }
`;

export const draftWorksQuery = graphql`
    query DraftWorksQuery(
        $count: Int,
        $cursor: ID,
        $orderBy: WorksOrdering,
        $orderMode: OrderingMode,
        $search: String,
        $filters: FilterGroup,
    ) {
        ...DraftWorksLines_data
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

const LOCAL_STORAGE_KEY = 'draft_works';

interface DraftWorksProps {
  draftId: string;
}

const DraftWorks : FunctionComponent<DraftWorksProps> = ({ draftId }) => {
  const initialValues = {
    filters: {
      ...emptyFilterGroup,
    },
    searchTerm: '',
    sortBy: 'timestamp',
    orderAsc: false,
  };

  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<DraftWorksQuery$variables>(LOCAL_STORAGE_KEY, initialValues, true);
  const { filters } = viewStorage;
  const currentDraftFilter = { key: 'draft_context', values: [draftId], operator: 'eq', mode: 'or' };
  const finalFilters = { ...filters, filters: [...(filters?.filters ?? []), currentDraftFilter] };
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: finalFilters,
  } as unknown as DraftWorksQuery$variables;

  const queryRef = useQueryLoading<DraftWorksQuery>(draftWorksQuery, queryPaginationOptions);

  const preloadedPaginationProps = {
    linesQuery: draftWorksQuery,
    linesFragment: draftWorksLinesFragment,
    queryRef,
    nodePath: ['works', 'pageInfo', 'globalCount'],
    setNumberOfElements: helpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<DraftWorksQuery>;

  const dataColumns: DataTableProps['dataColumns'] = {
    name: {
      percentWidth: 50,
      isSortable: false,
    },
    timestamp: {
      label: 'Timestamp',
      percentWidth: 25,
      isSortable: true,
      render: ({ timestamp }, h) => defaultRender(h.fd(timestamp)),
    },
    status: {
      label: 'Status',
      percentWidth: 25,
      isSortable: true,
      render: ({ status }) => defaultRender(status),
    },
  };

  return (
    <span data-testid="draft-works-page">
      {queryRef && (
      <DataTable
        dataColumns={dataColumns}
        resolvePath={(data: DraftWorksLines_data$data) => data.works?.edges?.map((n) => n?.node)}
        storageKey={LOCAL_STORAGE_KEY}
        initialValues={initialValues}
        preloadedPaginationProps={preloadedPaginationProps}
        variant={DataTableVariant.inline}
        disableNavigation
        disableLineSelection
        lineFragment={draftWorkLineFragment}
      />
      )}
    </span>
  );
};

export default DraftWorks;
