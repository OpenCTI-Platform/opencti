import React, { FunctionComponent, useState } from 'react';
import { DraftEntitiesLinesPaginationQuery, DraftEntitiesLinesPaginationQuery$variables } from '@components/drafts/__generated__/DraftEntitiesLinesPaginationQuery.graphql';
import { useParams } from 'react-router-dom';
import { graphql } from 'react-relay';
import { DraftEntitiesLines_data$data } from '@components/drafts/__generated__/DraftEntitiesLines_data.graphql';
import StixDomainObjectCreation from '@components/common/stix_domain_objects/StixDomainObjectCreation';
import StixCyberObservableCreation from '@components/observations/stix_cyber_observables/StixCyberObservableCreation';
import { Add } from '@mui/icons-material';
import Fab from '@mui/material/Fab';
import useAuth from '../../../utils/hooks/useAuth';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { useBuildEntityTypeBasedFilterContext, emptyFilterGroup } from '../../../utils/filters/filtersUtils';
import { UsePreloadedPaginationFragment } from '../../../utils/hooks/usePreloadedPaginationFragment';
import DataTable from '../../../components/dataGrid/DataTable';
import { DataTableProps } from '../../../components/dataGrid/dataTableTypes';
import useHelper from '../../../utils/hooks/useHelper';

const draftEntitiesLineFragment = graphql`
    fragment DraftEntities_node on StixCoreObject {
        id
        entity_type
        created_at
        representative {
          main
        }
        draftVersion {
          draft_operation
        }
        objectMarking {
            id
            definition
            x_opencti_order
            x_opencti_color
        }
        creators {
            id
            name
        }
    }
`;

const draftEntitiesLinesQuery = graphql`
    query DraftEntitiesLinesPaginationQuery(
        $draftId: String!
        $types: [String]
        $search: String
        $count: Int!
        $cursor: ID
        $orderBy: StixCoreObjectsOrdering
        $orderMode: OrderingMode
        $filters: FilterGroup
    ) {
        ...DraftEntitiesLines_data
        @arguments(
            draftId: $draftId
            types: $types
            search: $search
            count: $count
            cursor: $cursor
            orderBy: $orderBy
            orderMode: $orderMode
            filters: $filters
        )
    }
`;

export const draftEntitiesLinesFragment = graphql`
    fragment DraftEntitiesLines_data on Query
    @argumentDefinitions(
        draftId: { type: "String!" }
        types: { type: "[String]" }
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
        orderBy: { type: "StixCoreObjectsOrdering", defaultValue: name }
        orderMode: { type: "OrderingMode", defaultValue: asc }
        filters: { type: "FilterGroup" }
    )
    @refetchable(queryName: "DraftEntitiesLinesRefetchQuery") {
        draftWorkspaceEntities(
            draftId: $draftId
            types: $types
            search: $search
            first: $count
            after: $cursor
            orderBy: $orderBy
            orderMode: $orderMode
            filters: $filters
        ) @connection(key: "Pagination_draftWorkspaceEntities") {
            edges {
                node {
                    ...DraftEntities_node
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

const LOCAL_STORAGE_KEY = 'draft_entities';

interface DraftEntitiesProps {
  entitiesType?: string;
}

const DraftEntities : FunctionComponent<DraftEntitiesProps> = ({
  entitiesType = 'Stix-Core-Object',
}) => {
  const { draftId } = useParams() as { draftId: string };
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');
  const [open, setOpen] = useState(false);
  const [openCreateEntity, setOpenCreateEntity] = useState(false);
  const [openCreateObservable, setOpenCreateObservable] = useState(false);
  const { platformModuleHelpers: { isRuntimeFieldEnable } } = useAuth();
  const handleCloseCreateEntity = () => {
    setOpenCreateEntity(false);
    setOpen(false);
  };
  const handleCloseCreateObservable = () => {
    setOpenCreateObservable(false);
    setOpen(false);
  };

  const initialValues = {
    filters: emptyFilterGroup,
    searchTerm: '',
    sortBy: 'name',
    orderAsc: false,
    openExports: false,
    redirectionMode: 'overview',
    draftId,
  };

  const {
    viewStorage,
    paginationOptions,
    helpers: storageHelpers,
  } = usePaginationLocalStorage<DraftEntitiesLinesPaginationQuery$variables>(LOCAL_STORAGE_KEY, initialValues);
  const {
    filters,
    searchTerm,
  } = viewStorage;

  const contextFilters = useBuildEntityTypeBasedFilterContext(entitiesType, filters);
  const queryPaginationOptions = {
    ...paginationOptions,
    draftId,
    filters: contextFilters,
  } as unknown as DraftEntitiesLinesPaginationQuery$variables;

  const queryRef = useQueryLoading<DraftEntitiesLinesPaginationQuery>(
    draftEntitiesLinesQuery,
    queryPaginationOptions,
  );

  const preloadedPaginationProps = {
    linesQuery: draftEntitiesLinesQuery,
    linesFragment: draftEntitiesLinesFragment,
    queryRef,
    nodePath: ['draftWorkspaceEntities', 'pageInfo', 'globalCount'],
    setNumberOfElements: storageHelpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<DraftEntitiesLinesPaginationQuery>;

  const isRuntimeSort = isRuntimeFieldEnable() ?? false;
  const dataColumns: DataTableProps['dataColumns'] = {
    draftVersion: {
      isSortable: false,
      percentWidth: 10,
    },
    entity_type: {
      percentWidth: 12,
      isSortable: true,
    },
    name: {
      percentWidth: 25,
      isSortable: true,
    },
    createdBy: {
      percentWidth: 10,
      isSortable: isRuntimeSort,
    },
    creator: {
      percentWidth: 10,
      isSortable: isRuntimeSort,
    },
    objectLabel: {
      percentWidth: 15,
      isSortable: false,
    },
    created_at: {
      percentWidth: 10,
      isSortable: true,
    },
    objectMarking: {
      isSortable: isRuntimeSort,
      percentWidth: 8,
    },
  };

  return (
    <span data-testid="draft-entities-page">
      {queryRef && (
        <DataTable
          dataColumns={dataColumns}
          resolvePath={(data: DraftEntitiesLines_data$data) => data.draftWorkspaceEntities?.edges?.map((n) => n?.node)}
          storageKey={LOCAL_STORAGE_KEY}
          initialValues={initialValues}
          toolbarFilters={contextFilters}
          preloadedPaginationProps={preloadedPaginationProps}
          lineFragment={draftEntitiesLineFragment}
          exportContext={{ entity_type: 'Stix-Domain-Object' }}
          redirectionModeEnabled
          disableSelectAll // TODO: To handle selectAll
          createButton={
            isFABReplaced && (
              entitiesType === 'Stix-Cyber-Observable' ? (
                <>
                  <Fab
                    onClick={() => setOpenCreateObservable(true)}
                    color="primary"
                    aria-label="Add"
                    style={{
                      position: 'fixed',
                      bottom: 30,
                      right: 30,
                      zIndex: 2000,
                    }}
                  >
                    <Add/>
                  </Fab>
                  <StixCyberObservableCreation
                    display={open}
                    contextual={true}
                    inputValue={searchTerm}
                    paginationKey="Pagination_draftWorkspaceEntities"
                    paginationOptions={queryPaginationOptions}
                    speeddial={true}
                    open={openCreateObservable}
                    handleClose={handleCloseCreateObservable}
                  />
                </>
              ) : (
                <>
                  <Fab
                    onClick={() => setOpenCreateEntity(true)}
                    color="primary"
                    aria-label="Add"
                    style={{
                      position: 'fixed',
                      bottom: 30,
                      right: 30,
                      zIndex: 2000,
                    }}
                  >
                    <Add/>
                  </Fab>
                  <StixDomainObjectCreation
                    display={open}
                    inputValue={searchTerm}
                    paginationKey="Pagination_stixCoreObjects"
                    paginationOptions={queryPaginationOptions}
                    speeddial={true}
                    open={openCreateEntity}
                    handleClose={handleCloseCreateEntity}
                    onCompleted={() => setOpenCreateEntity(false)}
                    creationCallback={undefined}
                    confidence={undefined}
                    defaultCreatedBy={undefined}
                    isFromBulkRelation={undefined}
                    defaultMarkingDefinitions={undefined}
                    stixDomainObjectTypes={undefined}
                  />
                </>
              ))
          }
        />
      )}
    </span>
  );
};

export default DraftEntities;
