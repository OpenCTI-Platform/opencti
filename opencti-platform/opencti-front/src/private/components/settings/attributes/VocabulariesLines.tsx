import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, usePaginationFragment, usePreloadedQuery } from 'react-relay';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { VocabularyLine, VocabularyLineDummy } from './VocabularyLine';
import { DataColumns } from '../../../../components/list_lines';
import {
  VocabulariesLines_DataQuery,
  VocabulariesLines_DataQuery$variables,
} from './__generated__/VocabulariesLines_DataQuery.graphql';
import { VocabulariesLines_data$key } from './__generated__/VocabulariesLines_data.graphql';
import { VocabulariesLinesPaginationQuery } from './__generated__/VocabulariesLinesPaginationQuery.graphql';

export interface VocabulariesLinesProps {
  paginationOptions: VocabulariesLines_DataQuery$variables,
  dataColumns: DataColumns,
  queryRef: PreloadedQuery<VocabulariesLinesPaginationQuery>,
}

export const vocabulariesLinesQuery = graphql`
  query VocabulariesLinesPaginationQuery(
    $search: String
    $count: Int
    $orderMode: OrderingMode
    $orderBy: VocabularyOrdering
    $filters: [VocabularyFiltering!]
  ) {
    ...VocabulariesLines_data
    @arguments(
      search: $search
      count: $count
      orderMode: $orderMode
      orderBy: $orderBy
      filters: $filters
    )
  }
`;

export const vocabulariesLinesFragment = graphql`
  fragment VocabulariesLines_data on Query
  @argumentDefinitions(
    filters: { type: "[VocabularyFiltering!]" }
    search: { type: "String" }
    count: { type: "Int", defaultValue: 200 }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    orderBy: { type: "VocabularyOrdering", defaultValue: name }
    after: { type: "ID", defaultValue: "" }
  )
  @refetchable(queryName: "VocabulariesLines_DataQuery")
  {
    vocabularies(
      filters: $filters
      search: $search
      first: $count
      orderMode: $orderMode
      orderBy: $orderBy
      after: $after
    ) @connection(key: "Pagination_vocabularies") {
      edges {
        node {
          ...useVocabularyCategory_Vocabularynode
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

const VocabulariesLines: FunctionComponent<VocabulariesLinesProps> = ({ queryRef, dataColumns, paginationOptions }) => {
  const queryData = usePreloadedQuery(vocabulariesLinesQuery, queryRef);
  const {
    data,
    refetch,
    hasNext,
    loadNext,
    isLoadingNext,
  } = usePaginationFragment<VocabulariesLines_DataQuery, VocabulariesLines_data$key>(vocabulariesLinesFragment, queryData);

  const vocabularies = data?.vocabularies?.edges ?? [];
  const globalCount = data?.vocabularies?.pageInfo?.globalCount;
  return (
    <ListLinesContent
      initialLoading={!queryData}
      loadMore={loadNext}
      hasMore={() => hasNext}
      refetch={refetch}
      isLoading={() => isLoadingNext}
      dataList={vocabularies}
      globalCount={globalCount}
      LineComponent={VocabularyLine}
      DummyLineComponent={VocabularyLineDummy}
      dataColumns={dataColumns}
      nbOfRowsToLoad={10}
      paginationOptions={paginationOptions}
    />
  );
};

export const vocabulariesQuery = graphql`
  query VocabulariesLinesQuery($category: VocabularyCategory!) {
    vocabularies(category: $category) {
      edges {
        node {
          id
          name
          description
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

export default VocabulariesLines;
