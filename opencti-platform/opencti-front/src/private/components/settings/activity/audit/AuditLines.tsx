import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import { AuditLine, AuditLineDummy } from './AuditLine';
import { AuditLine_node$data } from './__generated__/AuditLine_node.graphql';
import { AuditLinesPaginationQuery, AuditLinesPaginationQuery$variables } from './__generated__/AuditLinesPaginationQuery.graphql';
import { AuditLines_data$key } from './__generated__/AuditLines_data.graphql';
import { HandleAddFilter, UseLocalStorageHelpers } from '../../../../../utils/hooks/useLocalStorage';
import { DataColumns } from '../../../../../components/list_lines';
import usePreloadedPaginationFragment from '../../../../../utils/hooks/usePreloadedPaginationFragment';
import ListLinesContent from '../../../../../components/list_lines/ListLinesContent';

const nbOfRowsToLoad = 50;

const AuditLineFragment = graphql`
  fragment AuditLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    types: { type: "[String!]" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "LogsOrdering", defaultValue: timestamp }
    orderMode: { type: "OrderingMode", defaultValue: desc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "AuditLinesRefetchQuery") {
    audits(
      search: $search
      first: $count
      types: $types
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_audits") {
      edges {
        node {
          ...AuditLine_node
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

export const AuditLinesQuery = graphql`
  query AuditLinesPaginationQuery(
    $search: String
    $types: [String!]
    $count: Int
    $cursor: ID
    $orderBy: LogsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...AuditLines_data
      @arguments(
        search: $search
        types: $types
        count: $count
        cursor: $cursor
        orderBy: $orderBy
        orderMode: $orderMode
        filters: $filters
      )
  }
`;

interface AuditLinesProps {
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
  dataColumns: DataColumns;
  paginationOptions: AuditLinesPaginationQuery$variables;
  queryRef: PreloadedQuery<AuditLinesPaginationQuery>;
  selectedElements: Record<string, AuditLine_node$data>;
  deSelectedElements: Record<string, AuditLine_node$data>;
  onToggleEntity: (
    entity: AuditLine_node$data,
    event: React.SyntheticEvent,
  ) => void;
  selectAll: boolean;
  onLabelClick?: HandleAddFilter;
}

const AuditLines: FunctionComponent<AuditLinesProps> = ({
  paginationOptions,
  queryRef,
  dataColumns,
  onLabelClick,
  setNumberOfElements,
  onToggleEntity,
  selectedElements,
  deSelectedElements,
  selectAll,
}) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
  AuditLinesPaginationQuery,
  AuditLines_data$key
  >({
    linesQuery: AuditLinesQuery,
    linesFragment: AuditLineFragment,
    queryRef,
    nodePath: ['audits', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });

  return (
    <ListLinesContent
      initialLoading={!data}
      loadMore={loadMore}
      hasMore={hasMore}
      isLoading={isLoadingMore}
      dataList={data?.audits?.edges ?? []}
      globalCount={data?.audits?.pageInfo?.globalCount ?? nbOfRowsToLoad}
      LineComponent={AuditLine}
      DummyLineComponent={AuditLineDummy}
      dataColumns={dataColumns}
      nbOfRowsToLoad={nbOfRowsToLoad}
      paginationOptions={paginationOptions}
      onLabelClick={onLabelClick}
      selectedElements={selectedElements}
      deSelectedElements={deSelectedElements}
      selectAll={selectAll}
      onToggleEntity={onToggleEntity}
    />
  );
};

export default AuditLines;
