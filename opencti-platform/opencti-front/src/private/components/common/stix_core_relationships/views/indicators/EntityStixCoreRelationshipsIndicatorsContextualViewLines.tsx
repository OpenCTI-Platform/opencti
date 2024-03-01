import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import {
  EntityStixCoreRelationshipsIndicatorsContextualViewLinesQuery,
  EntityStixCoreRelationshipsIndicatorsContextualViewLinesQuery$variables,
} from './__generated__/EntityStixCoreRelationshipsIndicatorsContextualViewLinesQuery.graphql';
import { DataColumns } from '../../../../../../components/list_lines';
import { UseEntityToggle } from '../../../../../../utils/hooks/useEntityToggle';
import { EntityStixCoreRelationshipsIndicatorsContextualViewLine_node$data } from './__generated__/EntityStixCoreRelationshipsIndicatorsContextualViewLine_node.graphql';
import { UseLocalStorageHelpers } from '../../../../../../utils/hooks/useLocalStorage';
import usePreloadedPaginationFragment from '../../../../../../utils/hooks/usePreloadedPaginationFragment';
import { EntityStixCoreRelationshipsIndicatorsContextualViewLines_data$key } from './__generated__/EntityStixCoreRelationshipsIndicatorsContextualViewLines_data.graphql';
import EntityStixCoreRelationshipsIndicatorsContextualViewLine from './EntityStixCoreRelationshipsIndicatorsContextualViewLine';
import EntityStixCoreRelationshipsContextualViewLineDummy from '../EntityStixCoreRelationshipsContextualViewLineDummy';
import useQueryLoading from '../../../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../../../components/Loader';
import ListLinesContent from '../../../../../../components/list_lines/ListLinesContent';

const nbOfRowsToLoad = 50;

const contextualViewLinesFragment = graphql`
  fragment EntityStixCoreRelationshipsIndicatorsContextualViewLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "IndicatorsOrdering", defaultValue: created_at }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "IndicatorsContextualViewLines_refetch") {
    indicators(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    )  @connection(key: "Pagination_indicators") {
      edges {
        node {
          ...EntityStixCoreRelationshipsIndicatorsContextualViewLine_node
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
  query EntityStixCoreRelationshipsIndicatorsContextualViewLinesQuery(
    $search: String
    $count: Int
    $cursor: ID
    $filters: FilterGroup
    $orderBy: IndicatorsOrdering
    $orderMode: OrderingMode
  ) {
    ...EntityStixCoreRelationshipsIndicatorsContextualViewLines_data
    @arguments(
      search: $search
      count: $count
      cursor: $cursor
      filters: $filters
      orderBy: $orderBy
      orderMode: $orderMode
    )
  }
`;

interface EntityStixCoreRelationshipsIndicatorsContextualViewLinesProps {
  queryRef: PreloadedQuery<EntityStixCoreRelationshipsIndicatorsContextualViewLinesQuery>
  dataColumns: DataColumns
  paginationOptions: Partial<EntityStixCoreRelationshipsIndicatorsContextualViewLinesQuery$variables>
  onToggleEntity: UseEntityToggle<EntityStixCoreRelationshipsIndicatorsContextualViewLine_node$data>['onToggleEntity']
  selectedElements: UseEntityToggle<EntityStixCoreRelationshipsIndicatorsContextualViewLine_node$data>['selectedElements']
  deSelectedElements: UseEntityToggle<EntityStixCoreRelationshipsIndicatorsContextualViewLine_node$data>['deSelectedElements']
  selectAll: UseEntityToggle<EntityStixCoreRelationshipsIndicatorsContextualViewLine_node$data>['selectAll']
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements']
}

const EntityStixCoreRelationshipsIndicatorsContextualViewLinesComponent: FunctionComponent<EntityStixCoreRelationshipsIndicatorsContextualViewLinesProps> = ({
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
  EntityStixCoreRelationshipsIndicatorsContextualViewLinesQuery,
  EntityStixCoreRelationshipsIndicatorsContextualViewLines_data$key
  >({
    queryRef,
    linesQuery: contextualViewLinesQuery,
    linesFragment: contextualViewLinesFragment,
    nodePath: ['indicators', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });

  return (
    <ListLinesContent
      initialLoading={false}
      loadMore={loadMore}
      hasMore={hasMore}
      isLoading={isLoadingMore}
      dataList={data?.indicators?.edges ?? []}
      globalCount={data?.indicators?.pageInfo?.globalCount ?? nbOfRowsToLoad}
      LineComponent={EntityStixCoreRelationshipsIndicatorsContextualViewLine}
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

const EntityStixCoreRelationshipsIndicatorsContextualViewLines: FunctionComponent<
Omit<EntityStixCoreRelationshipsIndicatorsContextualViewLinesProps, 'queryRef'>
> = (props) => {
  const queryRef = useQueryLoading<EntityStixCoreRelationshipsIndicatorsContextualViewLinesQuery>(
    contextualViewLinesQuery,
    { count: 25, ...props.paginationOptions },
  );
  return queryRef ? (
    <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
      <EntityStixCoreRelationshipsIndicatorsContextualViewLinesComponent {...props} queryRef={queryRef} />
    </React.Suspense>
  ) : (
    <Loader variant={LoaderVariant.inElement} />
  );
};

export default EntityStixCoreRelationshipsIndicatorsContextualViewLines;
