import React from 'react';
import ExportContextProvider from '../../../utils/ExportContextProvider';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../utils/filters/filtersUtils';
import { useFormatter } from '../../../components/i18n';
import Breadcrumbs from '../../../components/Breadcrumbs';
import useHelper from '../../../utils/hooks/useHelper';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';
import DataTable from '../../../components/dataGrid/DataTable';
import { graphql } from 'react-relay';
import { UsePreloadedPaginationFragment } from '../../../utils/hooks/usePreloadedPaginationFragment';
import ItemEntityType from '../../../components/ItemEntityType';
import { getMainRepresentative } from '../../../utils/defaultRepresentatives';
import { defaultRender } from '../../../components/dataGrid/dataTableUtils';
import { TrashDeleteOperationLine_node$data } from './__generated__/TrashDeleteOperationLine_node.graphql';
import DeleteOperationPopover from './DeleteOperationPopover';
import TrashInformation from './TrashInformation';
import { EMPTY_VALUE } from '../../../utils/String';
import { TrashDeleteOperationsLinesPaginationQuery, TrashDeleteOperationsLinesPaginationQuery$variables } from './__generated__/TrashDeleteOperationsLinesPaginationQuery.graphql';
import { TrashDeleteOperationsLines_data$data } from './__generated__/TrashDeleteOperationsLines_data.graphql';

const DeleteOperationFragment = graphql`
  fragment TrashDeleteOperationLine_node on DeleteOperation {
    id
    entity_type
    main_entity_name
    main_entity_type
    deletedBy {
      id
      name
    }
    created_at
    deleted_elements {
      id
    }
    objectMarking {
      id
      definition
      definition_type
      x_opencti_color
    }
  }
`;

export const deleteOperationsLinesQuery = graphql`
  query TrashDeleteOperationsLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: DeleteOperationOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...TrashDeleteOperationsLines_data
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

export const deleteOperationsLinesFragment = graphql`
  fragment TrashDeleteOperationsLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "DeleteOperationOrdering", defaultValue: created_at }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "DeleteOperationsLinesRefetchQuery") {
    deleteOperations(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_deleteOperations") {
      edges {
        node {
          id
          ...TrashDeleteOperationLine_node
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

const LOCAL_STORAGE_KEY = 'trash';

const Trash: React.FC = () => {
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Trash'));

  const initialValues = {
    searchTerm: '',
    sortBy: 'created_at',
    orderAsc: false,
    openExports: false,
    filters: emptyFilterGroup,
  };
  const {
    viewStorage,
    paginationOptions,
    helpers,
  } = usePaginationLocalStorage<TrashDeleteOperationsLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );
  const {
    filters,
  } = viewStorage;

  const contextFilters = useBuildEntityTypeBasedFilterContext('DeleteOperation', filters);

  const { isRuntimeFieldEnable } = useHelper();
  const isRuntimeSort = isRuntimeFieldEnable() ?? false;

  const queryRef = useQueryLoading<TrashDeleteOperationsLinesPaginationQuery>(
    deleteOperationsLinesQuery,
    paginationOptions,
  );

  const dataColumns = {
    main_entity_type: {
      label: 'Type',
      percentWidth: 12,
      isSortable: false,
      render: ({ main_entity_type }: TrashDeleteOperationLine_node$data) => <ItemEntityType showIcon entityType={main_entity_type} />,
    },
    main_entity_name: {
      label: 'Representation',
      percentWidth: 38,
      isSortable: true,
      render: (data: TrashDeleteOperationLine_node$data) => {
        return defaultRender(getMainRepresentative(data));
      },
    },
    deletedBy: {
      label: 'Deleted by',
      percentWidth: 20,
      isSortable: isRuntimeSort,
      render: ({ deletedBy }: TrashDeleteOperationLine_node$data) => deletedBy?.name ?? EMPTY_VALUE,
    },
    created_at: {
      label: 'Deletion date',
      percentWidth: 20,
    },
    objectMarking: {
      percentWidth: 10,
    },
  };

  const preloadedPaginationProps = {
    linesQuery: deleteOperationsLinesQuery,
    linesFragment: deleteOperationsLinesFragment,
    queryRef,
    nodePath: ['deleteOperations', 'pageInfo', 'globalCount'],
    setNumberOfElements: helpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<TrashDeleteOperationsLinesPaginationQuery>;

  const renderLines = () => {
    return (
      <div data-testid="trash-page">
        {queryRef && (
          <DataTable
            dataColumns={dataColumns}
            resolvePath={(data: TrashDeleteOperationsLines_data$data) => data.deleteOperations?.edges?.map((n) => n?.node)}
            storageKey={LOCAL_STORAGE_KEY}
            initialValues={initialValues}
            contextFilters={contextFilters}
            preloadedPaginationProps={preloadedPaginationProps}
            lineFragment={DeleteOperationFragment}
            exportContext={{ entity_type: 'DeleteOperation' }}
            disableNavigation
            trashOperationsEnabled
            disableBulkEnroll
            deleteDisable
            actions={(row: TrashDeleteOperationLine_node$data) => (
              <DeleteOperationPopover
                mainEntityId={row.id}
                deletedCount={row.deleted_elements.length}
                paginationOptions={paginationOptions}
              />
            )}
          />
        )}
      </div>
    );
  };
  return (
    <ExportContextProvider>
      <Breadcrumbs
        elements={[{ label: t_i18n('Trash'), current: true }]}
        adornment={<TrashInformation />}
      />
      {renderLines()}
    </ExportContextProvider>
  );
};

export default Trash;
