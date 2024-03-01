import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import { UseLocalStorageHelpers } from '../../../../../utils/hooks/useLocalStorage';
import { UseEntityToggle } from '../../../../../utils/hooks/useEntityToggle';
import useQueryLoading from '../../../../../utils/hooks/useQueryLoading';
import usePreloadedPaginationFragment from '../../../../../utils/hooks/usePreloadedPaginationFragment';
import ListLinesContent from '../../../../../components/list_lines/ListLinesContent';
import Loader, { LoaderVariant } from '../../../../../components/Loader';
import { DataColumns } from '../../../../../components/list_lines';
import {
  EntityStixCoreRelationshipsContextualViewLinesQuery,
  EntityStixCoreRelationshipsContextualViewLinesQuery$variables,
} from './__generated__/EntityStixCoreRelationshipsContextualViewLinesQuery.graphql';
import { EntityStixCoreRelationshipsContextualViewLine_node$data } from './__generated__/EntityStixCoreRelationshipsContextualViewLine_node.graphql';
import { EntityStixCoreRelationshipsContextualViewLines_data$key } from './__generated__/EntityStixCoreRelationshipsContextualViewLines_data.graphql';
import EntityStixCoreRelationshipsContextualViewLineDummy from './EntityStixCoreRelationshipsContextualViewLineDummy';
import EntityStixCoreRelationshipsContextualViewLine from './EntityStixCoreRelationshipsContextualViewLine';

const nbOfRowsToLoad = 50;

const contextualViewLinesFragment = graphql`
  fragment EntityStixCoreRelationshipsContextualViewLines_data on Query
  @argumentDefinitions(
    types: { type: "[String]" }
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "StixCoreObjectsOrdering", defaultValue: created_at }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "ContextualViewLines_refetch") {
    stixCoreObjects(
      types: $types
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    )  @connection(key: "Pagination_stixCoreObjects") {
      edges {
        node {
          ...EntityStixCoreRelationshipsContextualViewLine_node
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

export const contextualViewLinesQuery = graphql`
  query EntityStixCoreRelationshipsContextualViewLinesQuery(
    $types: [String]
    $search: String
    $count: Int
    $cursor: ID
    $filters: FilterGroup
    $orderBy: StixCoreObjectsOrdering
    $orderMode: OrderingMode
  ) {
    ...EntityStixCoreRelationshipsContextualViewLines_data
    @arguments(
      types: $types
      search: $search
      count: $count
      cursor: $cursor
      filters: $filters
      orderBy: $orderBy
      orderMode: $orderMode
    )
  }
`;

interface EntityStixCoreRelationshipsContextualViewLinesProps {
  queryRef: PreloadedQuery<EntityStixCoreRelationshipsContextualViewLinesQuery>
  dataColumns: DataColumns
  paginationOptions: Partial<EntityStixCoreRelationshipsContextualViewLinesQuery$variables>
  onToggleEntity: UseEntityToggle<EntityStixCoreRelationshipsContextualViewLine_node$data>['onToggleEntity']
  selectedElements: UseEntityToggle<EntityStixCoreRelationshipsContextualViewLine_node$data>['selectedElements']
  deSelectedElements: UseEntityToggle<EntityStixCoreRelationshipsContextualViewLine_node$data>['deSelectedElements']
  selectAll: UseEntityToggle<EntityStixCoreRelationshipsContextualViewLine_node$data>['selectAll']
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements']
}

const EntityStixCoreRelationshipsContextualViewLinesComponent: FunctionComponent<EntityStixCoreRelationshipsContextualViewLinesProps> = ({
  queryRef,
  dataColumns,
  paginationOptions,
  onToggleEntity,
  selectedElements,
  deSelectedElements,
  selectAll,
  setNumberOfElements,
}) => {
  const { data, loadMore, hasMore, isLoadingMore } = usePreloadedPaginationFragment<
  EntityStixCoreRelationshipsContextualViewLinesQuery,
  EntityStixCoreRelationshipsContextualViewLines_data$key
  >({
    queryRef,
    linesQuery: contextualViewLinesQuery,
    linesFragment: contextualViewLinesFragment,
    nodePath: ['stixCoreObjects', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });

  return (
    <ListLinesContent
      initialLoading={false}
      loadMore={loadMore}
      hasMore={hasMore}
      isLoading={isLoadingMore}
      dataList={data?.stixCoreObjects?.edges ?? []}
      globalCount={data?.stixCoreObjects?.pageInfo?.globalCount ?? nbOfRowsToLoad}
      LineComponent={EntityStixCoreRelationshipsContextualViewLine}
      DummyLineComponent={EntityStixCoreRelationshipsContextualViewLineDummy}
      dataColumns={dataColumns}
      nbOfRowsToLoad={nbOfRowsToLoad}
      paginationOptions={paginationOptions}
      selectedElements={selectedElements}
      deSelectedElements={deSelectedElements}
      selectAll={selectAll}
      onToggleEntity={onToggleEntity}
    />
  );
};

const EntityStixCoreRelationshipsContextualViewLines: FunctionComponent<
Omit<EntityStixCoreRelationshipsContextualViewLinesProps, 'queryRef'>
> = (props) => {
  const queryRef = useQueryLoading<EntityStixCoreRelationshipsContextualViewLinesQuery>(
    contextualViewLinesQuery,
    { count: 25, ...props.paginationOptions },
  );
  return queryRef ? (
    <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
      <EntityStixCoreRelationshipsContextualViewLinesComponent {...props} queryRef={queryRef} />
    </React.Suspense>
  ) : (
    <Loader variant={LoaderVariant.inElement} />
  );
};

export default EntityStixCoreRelationshipsContextualViewLines;
