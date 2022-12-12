import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import {
  ContainerStixCyberObservableLine,
  ContainerStixCyberObservableLineDummy,
} from './ContainerStixCyberObservableLine';
import Security from '../../../../utils/Security';
import ContainerAddStixCoreObjects from './ContainerAddStixCoreObjects';
import { StixCyberObservableLine_node$data } from '../../observations/stix_cyber_observables/__generated__/StixCyberObservableLine_node.graphql';
import {
  ContainerStixCyberObservablesLinesQuery,
  ContainerStixCyberObservablesLinesQuery$variables,
} from './__generated__/ContainerStixCyberObservablesLinesQuery.graphql';
import { DataColumns } from '../../../../components/list_lines';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { ContainerStixCyberObservablesLines_container$key } from './__generated__/ContainerStixCyberObservablesLines_container.graphql';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import { UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';

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
    $filters: [StixObjectOrStixRelationshipsFiltering]
  ) {
    ...ContainerStixCyberObservablesLines_container
      @arguments(
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
    types: { type: "[String]" }
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: {
      type: "StixObjectOrStixRelationshipsOrdering"
      defaultValue: name
    }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "[StixObjectOrStixRelationshipsFiltering]" }
  )
  @refetchable(queryName: "ContainerStixCyberObservablesLinesRefetchQuery") {
    container(id: $id) {
      id
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
  openExports?: boolean;
  onToggleEntity: (
    entity:
    | StixCyberObservableLine_node$data
    | Array<StixCyberObservableLine_node$data>,
    event: React.SyntheticEvent,
    forceRemove: Array<StixCyberObservableLine_node$data>
  ) => void;
  selectedElements: Record<string, StixCyberObservableLine_node$data>;
  deSelectedElements: Record<string, StixCyberObservableLine_node$data>;
  selectAll: boolean;
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
  onTypesChange: (type: string) => void;
  queryRef: PreloadedQuery<ContainerStixCyberObservablesLinesQuery>;
  setSelectedElements: (
    selectedElements: Record<string, StixCyberObservableLine_node$data>
  ) => void;
}

const ContainerStixCyberObservablesLines: FunctionComponent<
ContainerStixCyberObservablesLinesProps
> = ({
  dataColumns,
  paginationOptions,
  openExports,
  onToggleEntity,
  selectedElements,
  deSelectedElements,
  selectAll,
  setNumberOfElements,
  onTypesChange,
  queryRef,
  setSelectedElements,
}) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
  ContainerStixCyberObservablesLinesQuery,
  ContainerStixCyberObservablesLines_container$key
  >({
    linesQuery: containerStixCyberObservablesLinesQuery,
    linesFragment: ContainerStixCyberObservablesLinesFragment,
    queryRef,
    nodePath: ['container', 'objects', 'edges'],
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
      />
      <Security needs={[KNOWLEDGE_KNUPDATE]}>
        <ContainerAddStixCoreObjects
          containerId={data?.container?.id}
          containerStixCoreObjects={data?.container?.objects?.edges ?? []}
          paginationOptions={paginationOptions}
          withPadding={true}
          targetStixCoreObjectTypes={['Stix-Cyber-Observable']}
          onTypesChange={onTypesChange}
          openExports={openExports}
        />
      </Security>
    </div>
  );
};

export default ContainerStixCyberObservablesLines;
