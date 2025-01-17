import React from 'react';
import { DraftsLinesPaginationQuery, DraftsLinesPaginationQuery$variables } from '@components/drafts/__generated__/DraftsLinesPaginationQuery.graphql';
import DraftCreation from '@components/drafts/DraftCreation';
import { graphql } from 'react-relay';
import { DraftsLines_data$data } from '@components/drafts/__generated__/DraftsLines_data.graphql';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import { useFormatter } from '../../../components/i18n';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../utils/filters/filtersUtils';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import Breadcrumbs from '../../../components/Breadcrumbs';
import { DataTableProps } from '../../../components/dataGrid/dataTableTypes';
import { UsePreloadedPaginationFragment } from '../../../utils/hooks/usePreloadedPaginationFragment';
import DataTable from '../../../components/dataGrid/DataTable';
import useHelper from '../../../utils/hooks/useHelper';
import DraftPopover from './DraftPopover';
import useDraftContext from '../../../utils/hooks/useDraftContext';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';

const DraftLineFragment = graphql`
    fragment Drafts_node on DraftWorkspace {
        id
        entity_type
        name
        creators {
          id
          name
        }
        created_at
    }
`;
export const draftsLinesQuery = graphql`
    query DraftsLinesPaginationQuery(
        $search: String
        $count: Int!
        $cursor: ID
        $orderBy: DraftWorkspacesOrdering
        $orderMode: OrderingMode
        $filters: FilterGroup
    ) {
        ...DraftsLines_data
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

export const draftsLinesFragment = graphql`
    fragment DraftsLines_data on Query
    @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
        orderBy: { type: "DraftWorkspacesOrdering", defaultValue: name }
        orderMode: { type: "OrderingMode", defaultValue: asc }
        filters: { type: "FilterGroup" }
    )
    @refetchable(queryName: "DraftsLinesRefetchQuery") {
        draftWorkspaces(
            search: $search
            first: $count
            after: $cursor
            orderBy: $orderBy
            orderMode: $orderMode
            filters: $filters
        ) @connection(key: "Pagination_draftWorkspaces") {
            edges {
                node {
                    id
                    ...Drafts_node
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

const LOCAL_STORAGE_KEY = 'draftWorkspaces';

const Drafts: React.FC = () => {
  const { t_i18n } = useFormatter();
  const draftContext = useDraftContext();
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Drafts'));

  const initialValues = {
    filters: emptyFilterGroup,
    searchTerm: '',
    sortBy: 'name',
    orderAsc: false,
    openExports: false,
    redirectionMode: 'overview',
  };
  const {
    viewStorage,
    paginationOptions,
    helpers: storageHelpers,
  } = usePaginationLocalStorage<DraftsLinesPaginationQuery$variables>(LOCAL_STORAGE_KEY, initialValues);
  const {
    filters,
  } = viewStorage;

  const contextFilters = useBuildEntityTypeBasedFilterContext('DraftWorkspace', filters);
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as DraftsLinesPaginationQuery$variables;
  const queryRef = useQueryLoading<DraftsLinesPaginationQuery>(
    draftsLinesQuery,
    queryPaginationOptions,
  );

  const preloadedPaginationProps = {
    linesQuery: draftsLinesQuery,
    linesFragment: draftsLinesFragment,
    queryRef,
    nodePath: ['draftWorkspaces', 'pageInfo', 'globalCount'],
    setNumberOfElements: storageHelpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<DraftsLinesPaginationQuery>;

  const dataColumns: DataTableProps['dataColumns'] = {
    name: {
      percentWidth: 50,
      isSortable: true,
    },
    creator: {
      percentWidth: 25,
      isSortable: true,
    },
    created_at: {
      percentWidth: 25,
      isSortable: true,
    },
  };

  return (
    <span data-testid="draft-page">
      <Breadcrumbs elements={[{ label: t_i18n('Drafts'), current: true }]} />
      {queryRef && (
      <DataTable
        dataColumns={dataColumns}
        resolvePath={(data: DraftsLines_data$data) => (data.draftWorkspaces?.edges ?? []).map((n) => n?.node)}
        storageKey={LOCAL_STORAGE_KEY}
        initialValues={initialValues}
        toolbarFilters={contextFilters}
        preloadedPaginationProps={preloadedPaginationProps}
        lineFragment={DraftLineFragment}
        exportContext={{ entity_type: 'DraftWorkspace' }}
        redirectionModeEnabled
        createButton={!draftContext && isFABReplaced && (
          <DraftCreation paginationOptions={queryPaginationOptions} />
        )}
        actions={(row) => (
          <DraftPopover
            draftId={row.id}
            paginationOptions={queryPaginationOptions}
          />
        )}
      />
      )}
      {!draftContext && !isFABReplaced && (
        <DraftCreation paginationOptions={queryPaginationOptions} />
      )}
    </span>
  );
};

export default Drafts;
