import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import { EntityStixSightingRelationshipsLines_data$key } from '@components/events/stix_sighting_relationships/__generated__/EntityStixSightingRelationshipsLines_data.graphql';
import {
  EntityStixSightingRelationshipsLinesPaginationQuery,
  EntityStixSightingRelationshipsLinesPaginationQuery$variables,
} from '@components/events/stix_sighting_relationships/__generated__/EntityStixSightingRelationshipsLinesPaginationQuery.graphql';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { EntityStixSightingRelationshipLine, EntityStixSightingRelationshipLineDummy } from './EntityStixSightingRelationshipLine';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { DataColumns } from '../../../../components/list_lines';
import { HandleAddFilter, UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';

const nbOfRowsToLoad = 50;

export const entityStixSightingRelationshipsLinesQuery = graphql`
  query EntityStixSightingRelationshipsLinesPaginationQuery(
    $fromId: StixRef
    $toId: StixRef
    $toTypes: [String]
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: StixSightingRelationshipsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...EntityStixSightingRelationshipsLines_data
    @arguments(
      fromId: $fromId
      toId: $toId
      toTypes: $toTypes
      search: $search
      count: $count
      cursor: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    )
  }
`;

export const EntityStixSightingRelationshipsLinesFragment = graphql`
  fragment EntityStixSightingRelationshipsLines_data on Query
  @argumentDefinitions(
    fromId: { type: "StixRef" }
    toId: { type: "StixRef" }
    toTypes: { type: "[String]" }
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: {
      type: "StixSightingRelationshipsOrdering"
      defaultValue: first_seen
    }
    orderMode: { type: "OrderingMode", defaultValue: desc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "EntityStixSightingRelationshipsLinesRefetchQuery") {
    stixSightingRelationships(
      fromId: $fromId
      toId: $toId
      toTypes: $toTypes
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_stixSightingRelationships") {
      edges {
        node {
          ...EntityStixSightingRelationshipLine_node
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

interface EntityStixSightingRelationshipsLinesProps {
  paginationOptions?: EntityStixSightingRelationshipsLinesPaginationQuery$variables;
  dataColumns: DataColumns;
  queryRef: PreloadedQuery<EntityStixSightingRelationshipsLinesPaginationQuery>;
  entityLink: string;
  isTo: boolean;
  onLabelClick: HandleAddFilter;
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
}

const EntityStixSightingRelationshipsLines: FunctionComponent<EntityStixSightingRelationshipsLinesProps> = ({
  dataColumns,
  queryRef,
  paginationOptions,
  entityLink,
  isTo,
  onLabelClick,
  setNumberOfElements,
}) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
  EntityStixSightingRelationshipsLinesPaginationQuery,
  EntityStixSightingRelationshipsLines_data$key
  >({
    linesQuery: entityStixSightingRelationshipsLinesQuery,
    linesFragment: EntityStixSightingRelationshipsLinesFragment,
    queryRef,
    nodePath: ['stixSightingRelationships', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });
  return (
    <ListLinesContent
      initialLoading={!data}
      loadMore={loadMore}
      hasMore={hasMore}
      isLoading={isLoadingMore}
      dataList={data?.stixSightingRelationships?.edges ?? []}
      globalCount={data?.stixSightingRelationships?.pageInfo?.globalCount ?? nbOfRowsToLoad}
      LineComponent={EntityStixSightingRelationshipLine}
      DummyLineComponent={EntityStixSightingRelationshipLineDummy}
      dataColumns={dataColumns}
      nbOfRowsToLoad={nbOfRowsToLoad}
      paginationOptions={paginationOptions}
      entityLink={entityLink}
      isTo={isTo}
      onLabelClick={onLabelClick}
    />
  );
};

export default EntityStixSightingRelationshipsLines;
