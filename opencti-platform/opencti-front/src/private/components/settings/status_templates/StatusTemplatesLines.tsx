import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import StatusTemplateLine, { DataColumnsType } from './StatusTemplateLine';
import StatusTemplateLineDummy from './StatusTemplateLineDummy';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { StatusTemplatesLinesPaginationQuery, StatusTemplatesLinesPaginationQuery$variables } from './__generated__/StatusTemplatesLinesPaginationQuery.graphql';
import { StatusTemplatesLines_data$key } from './__generated__/StatusTemplatesLines_data.graphql';
import { UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';

const nbOfRowsToLoad = 50;

interface StatusTemplatesLinesProps {
  queryRef: PreloadedQuery<StatusTemplatesLinesPaginationQuery>;
  dataColumns: DataColumnsType;
  paginationOptions: StatusTemplatesLinesPaginationQuery$variables;
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
}

export const statusTemplatesLinesQuery = graphql`
  query StatusTemplatesLinesPaginationQuery(
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: StatusTemplateOrdering
    $orderMode: OrderingMode
  ) {
    ...StatusTemplatesLines_data
      @arguments(
        search: $search
        count: $count
        cursor: $cursor
        orderBy: $orderBy
        orderMode: $orderMode
      )
  }
`;

const statusTemplatesLinesFragment = graphql`
  fragment StatusTemplatesLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "StatusTemplateOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
  )
  @refetchable(queryName: "StatusTemplatesLinesRefetchQuery") {
    statusTemplates(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
    ) @connection(key: "Pagination_statusTemplates") {
      edges {
        node {
          ...StatusTemplateLine_node
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

const StatusTemplatesLines: FunctionComponent<StatusTemplatesLinesProps> = ({
  queryRef,
  dataColumns,
  paginationOptions,
  setNumberOfElements,
}) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
  StatusTemplatesLinesPaginationQuery,
  StatusTemplatesLines_data$key
  >({
    linesQuery: statusTemplatesLinesQuery,
    linesFragment: statusTemplatesLinesFragment,
    queryRef,
    nodePath: ['statusTemplates', 'edges'],
    setNumberOfElements,
  });
  return (
    <ListLinesContent
      initialLoading={!data}
      loadMore={loadMore}
      hasMore={hasMore}
      isLoading={isLoadingMore}
      dataList={data?.statusTemplates?.edges ?? []}
      globalCount={
        data?.statusTemplates?.pageInfo?.globalCount ?? nbOfRowsToLoad
      }
      LineComponent={StatusTemplateLine}
      DummyLineComponent={StatusTemplateLineDummy}
      dataColumns={dataColumns}
      nbOfRowsToLoad={nbOfRowsToLoad}
      paginationOptions={paginationOptions}
    />
  );
};

export default StatusTemplatesLines;
