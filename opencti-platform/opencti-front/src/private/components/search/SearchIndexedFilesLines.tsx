import React, { FunctionComponent } from 'react';
import {
  SearchIndexedFilesLinesPaginationQuery,
  SearchIndexedFilesLinesPaginationQuery$variables,
} from '@components/search/__generated__/SearchIndexedFilesLinesPaginationQuery.graphql';
import { SearchIndexedFilesLines_data$key } from '@components/search/__generated__/SearchIndexedFilesLines_data.graphql';
import { graphql, PreloadedQuery } from 'react-relay';
import ListLinesContent from '../../../components/list_lines/ListLinesContent';
import usePreloadedPaginationFragment from '../../../utils/hooks/usePreloadedPaginationFragment';
import { HandleAddFilter, UseLocalStorageHelpers } from '../../../utils/hooks/useLocalStorage';
import { DataColumns } from '../../../components/list_lines';
import SearchIndexedFileLine from './SearchIndexedFileLine';

const nbOfRowsToLoad = 50;

interface SearchIndexedFilesLinesProps {
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
  dataColumns: DataColumns;
  paginationOptions: SearchIndexedFilesLinesPaginationQuery$variables;
  queryRef: PreloadedQuery<SearchIndexedFilesLinesPaginationQuery>;
  onLabelClick?: HandleAddFilter;
  redirectionMode?: string;
}

export const searchIndexedFilesLinesQuery = graphql`
    query SearchIndexedFilesLinesPaginationQuery(
        $search: String
        $first: Int
        $cursor: ID
    ) {
        ...SearchIndexedFilesLines_data
        @arguments(
            search: $search
            first: $first
            cursor: $cursor
        )
    }
`;

export const searchIndexedFilesLinesFragment = graphql`
    fragment SearchIndexedFilesLines_data on Query
    @argumentDefinitions(
        search: { type: "String" }
        first: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
    )
    @refetchable(queryName: "SearchIndexedFilesLinesRefetchQuery") {
        indexedFiles(
            search: $search
            first: $first
            after: $cursor
        ) @connection(key: "Pagination_indexedFiles") {
            edges {
                node {
                  ...SearchIndexedFileLine_node
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

const SearchIndexedFilesLines: FunctionComponent<SearchIndexedFilesLinesProps> = ({
  dataColumns,
  onLabelClick,
  paginationOptions,
  setNumberOfElements,
  queryRef,
}) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment <
  SearchIndexedFilesLinesPaginationQuery,
  SearchIndexedFilesLines_data$key
  >({
    linesQuery: searchIndexedFilesLinesQuery,
    linesFragment: searchIndexedFilesLinesFragment,
    queryRef,
    nodePath: ['indexedFiles', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });

  return (
    <ListLinesContent
      initialLoading={!data}
      loadMore={loadMore}
      hasMore={hasMore}
      isLoading={isLoadingMore}
      dataList={data?.indexedFiles?.edges ?? []}
      globalCount={
        data?.indexedFiles?.pageInfo?.globalCount ?? nbOfRowsToLoad
      }
      LineComponent={SearchIndexedFileLine}
      dataColumns={dataColumns}
      nbOfRowsToLoad={nbOfRowsToLoad}
      onLabelClick={onLabelClick}
      paginationOptions={paginationOptions}
    />
  );
};

export default SearchIndexedFilesLines;
