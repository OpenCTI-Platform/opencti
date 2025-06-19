import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { ContainerStixCyberObservableLine, ContainerStixCyberObservableLineDummy } from './ContainerStixCyberObservableLine';
import { ContainerStixCyberObservablesLinesQuery, ContainerStixCyberObservablesLinesQuery$variables } from './__generated__/ContainerStixCyberObservablesLinesQuery.graphql';
import { DataColumns } from '../../../../components/list_lines';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { ContainerStixCyberObservablesLines_container$key } from './__generated__/ContainerStixCyberObservablesLines_container.graphql';
import { UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';
import { ContainerStixCyberObservableLine_node$data } from './__generated__/ContainerStixCyberObservableLine_node.graphql';

const nbOfRowsToLoad = 50;

export const containerStixCyberObservablesLinesQuery = graphql`
  query ContainerStixCyberObservablesLinesQuery(
    $id: String!
    $types: [String]
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: StixObjectOrStixRelationshipsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...ContainerStixCyberObservablesLines_container
      @arguments(
        id: $id
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

const ContainerStixCyberObservablesLinesFragment = graphql`
  fragment ContainerStixCyberObservablesLines_container on Query
  @argumentDefinitions(
    id: { type: "String!" }
    types: { type: "[String]" }
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: {
      type: "StixObjectOrStixRelationshipsOrdering"
      defaultValue: name
    }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "ContainerStixCyberObservablesLinesRefetchQuery") {
    container(id: $id) {
      id
      confidence
      createdBy {
        ... on Identity {
          id
          name
          entity_type
        }
      }
      objectMarking {
        id
        definition_type
        definition
        x_opencti_order
        x_opencti_color
      }
      objects(
        types: $types
        search: $search
        first: $count
        after: $cursor
        orderBy: $orderBy
        orderMode: $orderMode
        filters: $filters
      ) @connection(key: "Pagination_objects") {
        edges {
          types
          node {
            ... on StixCyberObservable {
              id
              observable_value
              entity_type
            }
            ...ContainerStixCyberObservableLine_node
          }
        }
        pageInfo {
          endCursor
          hasNextPage
          globalCount
        }
      }
    }
  }
`;

interface ContainerStixCyberObservablesLinesProps {
  dataColumns: DataColumns;
  paginationOptions: ContainerStixCyberObservablesLinesQuery$variables;
  onToggleEntity: (
    entity: ContainerStixCyberObservableLine_node$data,
    event: React.SyntheticEvent,
    forceRemove: ContainerStixCyberObservableLine_node$data[]
  ) => void;
  selectedElements: Record<string, ContainerStixCyberObservableLine_node$data>;
  deSelectedElements: Record<
  string,
  ContainerStixCyberObservableLine_node$data
  >;
  selectAll: boolean;
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
  queryRef: PreloadedQuery<ContainerStixCyberObservablesLinesQuery>;
  setSelectedElements: (
    selectedElements: Record<string, ContainerStixCyberObservableLine_node$data>
  ) => void;
  enableReferences?: boolean;
}

const ContainerStixCyberObservablesLines: FunctionComponent<
ContainerStixCyberObservablesLinesProps
> = ({
  dataColumns,
  paginationOptions,
  onToggleEntity,
  selectedElements,
  deSelectedElements,
  selectAll,
  setNumberOfElements,
  queryRef,
  setSelectedElements,
  enableReferences,
}) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
  ContainerStixCyberObservablesLinesQuery,
  ContainerStixCyberObservablesLines_container$key
  >({
    linesQuery: containerStixCyberObservablesLinesQuery,
    linesFragment: ContainerStixCyberObservablesLinesFragment,
    queryRef,
    nodePath: ['container', 'objects', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });

  const numberOfElements = data?.container?.objects?.pageInfo?.globalCount;

  return (
    <div>
      <ListLinesContent
        initialLoading={!data}
        hasMore={hasMore}
        loadMore={loadMore}
        isLoading={isLoadingMore}
        dataList={data?.container?.objects?.edges ?? []}
        paginationOptions={paginationOptions}
        globalCount={numberOfElements ?? nbOfRowsToLoad}
        LineComponent={
          <ContainerStixCyberObservableLine
            containerId={data?.container?.id}
            setSelectedElements={setSelectedElements}
          />
        }
        DummyLineComponent={<ContainerStixCyberObservableLineDummy />}
        dataColumns={dataColumns}
        nbOfRowsToLoad={nbOfRowsToLoad}
        selectedElements={selectedElements}
        deSelectedElements={deSelectedElements}
        selectAll={selectAll}
        onToggleEntity={onToggleEntity}
        enableReferences={enableReferences}
      />
    </div>
  );
};

export default ContainerStixCyberObservablesLines;
