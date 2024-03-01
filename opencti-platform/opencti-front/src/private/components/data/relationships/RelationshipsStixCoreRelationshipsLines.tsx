import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import { RelationshipsStixCoreRelationshipLine_node$data } from '@components/data/relationships/__generated__/RelationshipsStixCoreRelationshipLine_node.graphql';
import {
  RelationshipsStixCoreRelationshipsLinesPaginationQuery,
  RelationshipsStixCoreRelationshipsLinesPaginationQuery$variables,
} from '@components/data/relationships/__generated__/RelationshipsStixCoreRelationshipsLinesPaginationQuery.graphql';
import { RelationshipsStixCoreRelationshipsLines_data$key } from '@components/data/relationships/__generated__/RelationshipsStixCoreRelationshipsLines_data.graphql';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { RelationshipsStixCoreRelationshipLine, RelationshipsStixCoreRelationshipLineDummy } from './RelationshipsStixCoreRelationshipLine';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { HandleAddFilter, UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';
import { DataColumns } from '../../../../components/list_lines';

const nbOfRowsToLoad = 50;

interface RelationshipsStixCoreRelationshipsLinesProps {
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
  dataColumns: DataColumns;
  paginationOptions: RelationshipsStixCoreRelationshipsLinesPaginationQuery$variables;
  queryRef: PreloadedQuery<RelationshipsStixCoreRelationshipsLinesPaginationQuery>;
  selectedElements: Record<string, RelationshipsStixCoreRelationshipLine_node$data>;
  deSelectedElements: Record<string, RelationshipsStixCoreRelationshipLine_node$data>;
  onToggleEntity: (
    entity: RelationshipsStixCoreRelationshipLine_node$data,
    event: React.SyntheticEvent
  ) => void;
  selectAll: boolean;
  onLabelClick?: HandleAddFilter;
}

export const relationshipsStixCoreRelationshipsLinesQuery = graphql`
  query RelationshipsStixCoreRelationshipsLinesPaginationQuery(
    $search: String
    $fromId: [String]
    $toId: [String]
    $fromTypes: [String]
    $toTypes: [String]
    $count: Int
    $cursor: ID
    $orderBy: StixCoreRelationshipsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...RelationshipsStixCoreRelationshipsLines_data
    @arguments(
      search: $search
      fromId: $fromId
      toId: $toId
      fromTypes: $fromTypes
      toTypes: $toTypes
      count: $count
      cursor: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    )
  }
`;

export const relationshipsStixCoreRelationshipsLinesFragment = graphql`
  fragment RelationshipsStixCoreRelationshipsLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    fromId: { type: "[String]" }
    toId: { type: "[String]" }
    fromTypes: { type: "[String]" }
    toTypes: { type: "[String]" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: {
      type: "StixCoreRelationshipsOrdering"
      defaultValue: created
    }
    orderMode: { type: "OrderingMode", defaultValue: desc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "RelationshipsStixCoreRelationshipsLinesRefetchQuery") {
    stixCoreRelationships(
      search: $search
      fromId: $fromId
      toId: $toId
      fromTypes: $fromTypes
      toTypes: $toTypes
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_stixCoreRelationships") {
      edges {
        node {
          id
          entity_type
          created_at
          createdBy {
            ... on Identity {
              name
            }
          }
          objectMarking {
            id
            definition_type
            definition
            x_opencti_order
            x_opencti_color
          }
          ...RelationshipsStixCoreRelationshipLine_node
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
const RelationshipsStixCoreRelationshipsLines: FunctionComponent<RelationshipsStixCoreRelationshipsLinesProps> = ({
  dataColumns,
  onLabelClick,
  onToggleEntity,
  selectedElements,
  deSelectedElements,
  selectAll,
  paginationOptions,
  setNumberOfElements,
  queryRef,
}) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
  RelationshipsStixCoreRelationshipsLinesPaginationQuery,
  RelationshipsStixCoreRelationshipsLines_data$key
  >({
    linesQuery: relationshipsStixCoreRelationshipsLinesQuery,
    linesFragment: relationshipsStixCoreRelationshipsLinesFragment,
    queryRef,
    nodePath: ['stixCoreRelationships', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });
  return (
    <ListLinesContent
      initialLoading={!data}
      loadMore={loadMore}
      hasMore={hasMore}
      isLoading={isLoadingMore}
      dataList={data?.stixCoreRelationships?.edges ?? []}
      globalCount={
        data?.stixCoreRelationships?.pageInfo?.globalCount ?? nbOfRowsToLoad
      }
      LineComponent={RelationshipsStixCoreRelationshipLine}
      DummyLineComponent={RelationshipsStixCoreRelationshipLineDummy}
      dataColumns={dataColumns}
      nbOfRowsToLoad={nbOfRowsToLoad}
      onLabelClick={onLabelClick}
      selectedElements={selectedElements}
      deSelectedElements={deSelectedElements}
      selectAll={selectAll}
      onToggleEntity={onToggleEntity}
      paginationOptions={paginationOptions}
    />
  );
};

export default RelationshipsStixCoreRelationshipsLines;
