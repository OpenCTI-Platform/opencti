import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { OpinionLine, OpinionLineDummy } from './OpinionLine';
import { HandleAddFilter, UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';
import { DataColumns } from '../../../../components/list_lines';
import { OpinionsLinesPaginationQuery, OpinionsLinesPaginationQuery$variables } from './__generated__/OpinionsLinesPaginationQuery.graphql';
import { OpinionLine_node$data } from './__generated__/OpinionLine_node.graphql';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { OpinionsLines_data$key } from './__generated__/OpinionsLines_data.graphql';

const nbOfRowsToLoad = 50;

export const opinionsLinesQuery = graphql`
  query OpinionsLinesPaginationQuery(
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: OpinionsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...OpinionsLines_data
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

const opinionsLineFragment = graphql`
  fragment OpinionsLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "OpinionsOrdering", defaultValue: created }
    orderMode: { type: "OrderingMode", defaultValue: desc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "OpinionsLinesRefetchQuery") {
    opinions(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_opinions") {
      edges {
        node {
          id
          opinion
          explanation
          created
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
          ...OpinionLine_node
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

interface OpinionsLinesProps {
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
  dataColumns: DataColumns; //
  paginationOptions: OpinionsLinesPaginationQuery$variables;
  queryRef: PreloadedQuery<OpinionsLinesPaginationQuery>;
  selectedElements: Record<string, OpinionLine_node$data>;
  deSelectedElements: Record<string, OpinionLine_node$data>;
  onToggleEntity: (
    entity: OpinionLine_node$data,
    event: React.SyntheticEvent
  ) => void; //
  selectAll: boolean; //
  onLabelClick?: HandleAddFilter; //
  redirectionMode?: string;
}

const OpinionsLines: FunctionComponent<OpinionsLinesProps> = ({
  dataColumns,
  onLabelClick,
  onToggleEntity,
  setNumberOfElements,
  selectedElements,
  deSelectedElements,
  selectAll,
  queryRef,
}) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
  OpinionsLinesPaginationQuery,
  OpinionsLines_data$key
  >({
    linesQuery: opinionsLinesQuery,
    linesFragment: opinionsLineFragment,
    queryRef,
    nodePath: ['opinions', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });
  return (
    <ListLinesContent
      initialLoading={!data}
      loadMore={loadMore}
      hasMore={hasMore}
      isLoading={isLoadingMore}
      dataList={data?.opinions?.edges ?? []}
      globalCount={data?.opinions?.pageInfo?.globalCount ?? nbOfRowsToLoad}
      LineComponent={<OpinionLine/>}
      DummyLineComponent={<OpinionLineDummy/>}
      dataColumns={dataColumns}
      nbOfRowsToLoad={nbOfRowsToLoad}
      onLabelClick={onLabelClick}
      selectedElements={selectedElements}
      deSelectedElements={deSelectedElements}
      selectAll={selectAll}
      onToggleEntity={onToggleEntity}
    />
  );
};

export default OpinionsLines;
