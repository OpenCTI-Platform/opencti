import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { IncidentLine, IncidentLineDummy } from './IncidentLine';
import { DataColumns } from '../../../../components/list_lines';
import { HandleAddFilter, UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { IncidentLine_node$data } from './__generated__/IncidentLine_node.graphql';
import { IncidentsLinesPaginationQuery, IncidentsLinesPaginationQuery$variables } from './__generated__/IncidentsLinesPaginationQuery.graphql';
import { IncidentsLines_data$key } from './__generated__/IncidentsLines_data.graphql';

const nbOfRowsToLoad = 50;

export const incidentsLinesPaginationQuery = graphql`
  query IncidentsLinesPaginationQuery(
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: IncidentsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...IncidentsLines_data
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

export const IncidentsLinesFragment = graphql`
  fragment IncidentsLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "IncidentsOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "IncidentsLinesRefetchQuery") {
    incidents(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_incidents") {
      edges {
        node {
          id
          name
          description
          ...IncidentLine_node
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

interface IncidentsLinesProps {
  paginationOptions?: IncidentsLinesPaginationQuery$variables;
  dataColumns: DataColumns;
  queryRef: PreloadedQuery<IncidentsLinesPaginationQuery>;
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
  onLabelClick: HandleAddFilter;
  selectedElements: Record<string, IncidentLine_node$data>;
  deSelectedElements: Record<string, IncidentLine_node$data>;
  onToggleEntity: (
    entity: IncidentLine_node$data,
    event: React.SyntheticEvent
  ) => void;
  selectAll: boolean;
}

const IncidentsLines: FunctionComponent<IncidentsLinesProps> = ({
  setNumberOfElements,
  dataColumns,
  queryRef,
  paginationOptions,
  onLabelClick,
  onToggleEntity,
  selectedElements,
  deSelectedElements,
  selectAll,
}) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
  IncidentsLinesPaginationQuery,
  IncidentsLines_data$key
  >({
    linesQuery: incidentsLinesPaginationQuery,
    linesFragment: IncidentsLinesFragment,
    queryRef,
    nodePath: ['incidents', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });
  return (
    <ListLinesContent
      initialLoading={!data}
      loadMore={loadMore}
      hasMore={hasMore}
      isLoading={isLoadingMore}
      dataList={data?.incidents?.edges ?? []}
      globalCount={data?.incidents?.pageInfo?.globalCount ?? nbOfRowsToLoad}
      LineComponent={IncidentLine}
      DummyLineComponent={IncidentLineDummy}
      dataColumns={dataColumns}
      nbOfRowsToLoad={nbOfRowsToLoad}
      onLabelClick={onLabelClick}
      paginationOptions={paginationOptions}
      selectedElements={selectedElements}
      deSelectedElements={deSelectedElements}
      selectAll={selectAll}
      onToggleEntity={onToggleEntity}
    />
  );
};
export default IncidentsLines;
