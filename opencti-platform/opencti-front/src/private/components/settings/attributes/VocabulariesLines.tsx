import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { VocabularyLine, VocabularyLineDummy } from './VocabularyLine';
import { DataColumns } from '../../../../components/list_lines';
import {
  VocabulariesLines_DataQuery,
  VocabulariesLines_DataQuery$variables,
} from './__generated__/VocabulariesLines_DataQuery.graphql';
import { VocabulariesLines_data$key } from './__generated__/VocabulariesLines_data.graphql';
import { VocabulariesLinesPaginationQuery } from './__generated__/VocabulariesLinesPaginationQuery.graphql';
import { useVocabularyCategory_Vocabularynode$data } from '../../../../utils/hooks/__generated__/useVocabularyCategory_Vocabularynode.graphql';
import { UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';

export interface VocabulariesLinesProps {
  paginationOptions: VocabulariesLines_DataQuery$variables;
  dataColumns: DataColumns;
  queryRef: PreloadedQuery<VocabulariesLinesPaginationQuery>;
  selectedElements: Record<string, useVocabularyCategory_Vocabularynode$data>;
  deSelectedElements: Record<string, useVocabularyCategory_Vocabularynode$data>;
  onToggleEntity: (
    entity: useVocabularyCategory_Vocabularynode$data,
    event: React.SyntheticEvent
  ) => void;
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
  selectAll: boolean;
}

export const vocabulariesLinesQuery = graphql`
  query VocabulariesLinesPaginationQuery(
    $search: String
    $count: Int
    $orderMode: OrderingMode
    $orderBy: VocabularyOrdering
    $filters: [VocabularyFiltering!]
    $category: VocabularyCategory
  ) {
    ...VocabulariesLines_data
      @arguments(
        search: $search
        count: $count
        orderMode: $orderMode
        orderBy: $orderBy
        filters: $filters
        category: $category
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
    after: { type: "ID" }
    category: { type: "VocabularyCategory" }
  )
  @refetchable(queryName: "VocabulariesLines_DataQuery") {
    vocabularies(
      filters: $filters
      search: $search
      first: $count
      orderMode: $orderMode
      orderBy: $orderBy
      after: $after
      category: $category
    ) @connection(key: "Pagination_vocabularies") {
      edges {
        node {
          id
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

const VocabulariesLines: FunctionComponent<VocabulariesLinesProps> = ({
  queryRef,
  dataColumns,
  paginationOptions,
  setNumberOfElements,
  selectedElements,
  deSelectedElements,
  selectAll,
  onToggleEntity,
}) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
  VocabulariesLines_DataQuery,
  VocabulariesLines_data$key
  >({
    queryRef,
    linesQuery: vocabulariesLinesQuery,
    linesFragment: vocabulariesLinesFragment,
    nodePath: ['vocabularies', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });

  const vocabularies = data?.vocabularies?.edges ?? [];
  const globalCount = data?.vocabularies?.pageInfo?.globalCount;

  return (
    <ListLinesContent
      initialLoading={!data}
      loadMore={loadMore}
      hasMore={hasMore}
      isLoading={isLoadingMore}
      dataList={vocabularies}
      globalCount={globalCount}
      LineComponent={VocabularyLine}
      DummyLineComponent={VocabularyLineDummy}
      dataColumns={dataColumns}
      nbOfRowsToLoad={10}
      paginationOptions={paginationOptions}
      selectedElements={selectedElements}
      deSelectedElements={deSelectedElements}
      onToggleEntity={onToggleEntity}
      selectAll={selectAll}
    />
  );
};

export default VocabulariesLines;
