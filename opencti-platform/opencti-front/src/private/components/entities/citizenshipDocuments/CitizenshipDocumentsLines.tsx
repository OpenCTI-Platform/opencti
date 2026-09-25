import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import {
  CitizenshipDocumentsLinesPaginationQuery,
  CitizenshipDocumentsLinesPaginationQuery$variables,
} from '@components/entities/citizenshipDocument/__generated__/CitizenshipDocumentsLinesPaginationQuery.graphql';
import { CitizenshipDocumentsLines_data$key } from '@components/entities/ctizenshipDocument/__generated__/CitizenshipDocumentsLines_data.graphql';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { CitizenshipDocumentLine, CitizenshipDocumentLineDummy } from './CitizenshipDocumentLine';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { DataColumns } from '../../../../components/list_lines';
import { HandleAddFilter, UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';

const nbOfRowsToLoad = 50;

interface CitizenshipDocumentsLinesProps {
  queryRef: PreloadedQuery<CitizenshipDocumentsLinesPaginationQuery>;
  dataColumns: DataColumns;
  paginationOptions?: CitizenshipDocumentsLinesPaginationQuery$variables;
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
  onLabelClick: HandleAddFilter;
}

export const citizenshipDocumentsLinesQuery = graphql`
  query CitizenshipDocumentsLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: CitizenshipDocumentsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...CitizenshipDocumentsLines_data
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

export const citizenshipDocumentsLinesFragment = graphql`
  fragment CitizenshipDocumentsLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "CitizenshipDocumentsOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "CitizenshipDocumentsLinesRefetchQuery") {
    citizenshipDocuments(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_citizenshipDocuments") {
      edges {
        node {
          id
          name
          description
          ...CitizenshipDocumentLine_node
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

const CitizenshipDocumentsLines: FunctionComponent<CitizenshipDocumentsLinesProps> = ({
  setNumberOfElements,
  queryRef,
  dataColumns,
  paginationOptions,
  onLabelClick,
}) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
    CitizenshipDocumentsLinesPaginationQuery,
    CitizenshipDocumentsLines_data$key
  >({
    linesQuery: citizenshipDocumentsLinesQuery,
    linesFragment: citizenshipDocumentsLinesFragment,
    queryRef,
    nodePath: ['citizenshipDocuments', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });

  return (
    <ListLinesContent
      initialLoading={!data}
      loadMore={loadMore}
      hasMore={hasMore}
      isLoading={isLoadingMore}
      dataList={data?.citizenshipDocuments?.edges ?? []}
      globalCount={
        data?.citizenshipDocuments?.pageInfo?.globalCount ?? nbOfRowsToLoad
      }
      LineComponent={CitizenshipDocumentLine}
      DummyLineComponent={CitizenshipDocumentLineDummy}
      dataColumns={dataColumns}
      nbOfRowsToLoad={nbOfRowsToLoad}
      paginationOptions={paginationOptions}
      onLabelClick={onLabelClick}
    />
  );
};

export default CitizenshipDocumentsLines;
