import React, { FunctionComponent } from 'react';
import { graphql } from 'react-relay';
import {
  DraftReviewEntityListPaginationQuery,
  DraftReviewEntityListPaginationQuery$variables,
} from '@components/drafts/__generated__/DraftReviewEntityListPaginationQuery.graphql';
import { DraftReviewEntityList_data$data } from '@components/drafts/__generated__/DraftReviewEntityList_data.graphql';
import { DraftReviewEntityList_node$data } from '@components/drafts/__generated__/DraftReviewEntityList_node.graphql';
import Tooltip from '@mui/material/Tooltip';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { UsePreloadedPaginationFragment } from '../../../utils/hooks/usePreloadedPaginationFragment';
import DataTable from '../../../components/dataGrid/DataTable';
import { DataTableProps, DataTableVariant } from '../../../components/dataGrid/dataTableTypes';
import { useBuildEntityTypeBasedFilterContext } from '../../../utils/filters/filtersUtils';

const draftReviewEntityFragment = graphql`
  fragment DraftReviewEntityList_node on StixCoreObject {
    id
    standard_id
    entity_type
    representative {
      main
    }
    draftVersion {
      draft_operation
      draft_updates_patch
    }
  }
`;

const draftReviewEntitiesLinesQuery = graphql`
  query DraftReviewEntityListPaginationQuery(
    $draftId: String!
    $count: Int!
    $cursor: ID
    $orderBy: StixCoreObjectsOrdering
    $orderMode: OrderingMode
    $draftOperation: DraftOperation
    $search: String
    $filters: FilterGroup
  ) {
    ...DraftReviewEntityList_data
    @arguments(
      draftId: $draftId
      count: $count
      cursor: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      draftOperation: $draftOperation
      search: $search
      filters: $filters
    )
  }
`;

const draftReviewEntitiesLinesFragment = graphql`
  fragment DraftReviewEntityList_data on Query
  @argumentDefinitions(
    draftId: { type: "String!" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "StixCoreObjectsOrdering", defaultValue: entity_type }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    draftOperation: { type: "DraftOperation" }
    search: { type: "String" }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "DraftReviewEntityListRefetchQuery") {
    draftWorkspaceEntities(
      draftId: $draftId
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      draftOperation: $draftOperation
      search: $search
      filters: $filters
    ) @connection(key: "DraftReviewEntityList__draftWorkspaceEntities") {
      edges {
        node {
          id
          draftVersion {
            draft_operation
          }
          ...DraftReviewEntityList_node
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

const getLocalStorageKey = (draftId: string) => `draft_review_entities_${draftId}`;

export interface DraftEntitySelection {
  id: string;
  entity_type: string;
  representative_main: string | null | undefined;
  draft_operation: string | null | undefined;
  draft_updates_patch: string | null | undefined;
}

interface DraftReviewEntityListProps {
  draftId: string;
  onSelectEntity: (data: DraftEntitySelection) => void;
  onQueryChange?: () => void;
  rootRef?: HTMLDivElement;
}

const DraftReviewEntityList: FunctionComponent<DraftReviewEntityListProps> = ({
  draftId,
  onSelectEntity,
  onQueryChange,
  rootRef,
}) => {
  const initialValues = {
    searchTerm: '',
    sortBy: 'entity_type',
    orderAsc: true,
    openExports: false,
    draftId,
  };

  const {
    viewStorage,
    paginationOptions,
    helpers: storageHelpers,
  } = usePaginationLocalStorage<DraftReviewEntityListPaginationQuery$variables>(getLocalStorageKey(draftId), initialValues);

  const {
    filters,
    searchTerm,
  } = viewStorage;

  React.useEffect(() => {
    onQueryChange?.();
  }, [searchTerm, filters, onQueryChange]);

  const contextFilters = useBuildEntityTypeBasedFilterContext('Stix-Core-Object', filters, { excludedEntityTypesParam: 'Container', draftId });

  const queryPaginationOptions = {
    ...paginationOptions,
    draftId,
  } as unknown as DraftReviewEntityListPaginationQuery$variables;

  const queryRef = useQueryLoading<DraftReviewEntityListPaginationQuery>(
    draftReviewEntitiesLinesQuery,
    queryPaginationOptions,
  );

  const preloadedPaginationProps = {
    linesQuery: draftReviewEntitiesLinesQuery,
    linesFragment: draftReviewEntitiesLinesFragment,
    queryRef,
    nodePath: ['draftWorkspaceEntities', 'pageInfo', 'globalCount'],
    setNumberOfElements: storageHelpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<DraftReviewEntityListPaginationQuery>;

  const dataColumns: DataTableProps['dataColumns'] = {
    draftVersion: {
      isSortable: false,
      percentWidth: 25,
    },
    entity_type: {
      percentWidth: 25,
      isSortable: true,
    },
    name: {
      label: 'Representation',
      percentWidth: 50,
      isSortable: false,
      render: (node: DraftReviewEntityList_node$data) => (
        <Tooltip title={node.representative?.main ?? node.id}>
          <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', display: 'block' }}>
            {node.representative?.main ?? node.id}
          </span>
        </Tooltip>
      ),
    },
  };

  return (
    <>
      {queryRef && (
        <DataTable
          rootRef={rootRef}
          dataColumns={dataColumns}
          resolvePath={(data: DraftReviewEntityList_data$data) => data.draftWorkspaceEntities?.edges
            ?.map((n) => n?.node)}
          storageKey={getLocalStorageKey(draftId)}
          initialValues={initialValues}
          contextFilters={contextFilters}
          preloadedPaginationProps={preloadedPaginationProps}
          lineFragment={draftReviewEntityFragment}
          disableLineSelection
          variant={DataTableVariant.inline}

          entityTypes={['Stix-Core-Object']}
          onLineClick={(node: DraftReviewEntityList_node$data) => {
            onSelectEntity({
              id: node.id,
              entity_type: node.entity_type,
              representative_main: node.representative?.main,
              draft_operation: node.draftVersion?.draft_operation ?? null,
              draft_updates_patch: node.draftVersion?.draft_updates_patch ?? null,
            });
          }}
        />
      )}
    </>
  );
};

export default DraftReviewEntityList;
