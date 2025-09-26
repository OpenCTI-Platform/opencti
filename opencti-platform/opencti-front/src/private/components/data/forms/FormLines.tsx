import { graphql, PreloadedQuery } from 'react-relay';
import React, { FunctionComponent } from 'react';
import { FormLinesPaginationQuery, FormLinesPaginationQuery$variables } from '@components/data/forms/__generated__/FormLinesPaginationQuery.graphql';
import { FormLines_data$key } from '@components/data/forms/__generated__/FormLines_data.graphql';
import { FormLineComponent, FormLineDummy } from '@components/data/forms/FormLine';
import { UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';
import { DataColumns } from '../../../../components/list_lines';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';

const nbOfRowsToLoad = 50;

interface FormLinesProps {
  queryRef: PreloadedQuery<FormLinesPaginationQuery>;
  dataColumns: DataColumns;
  paginationOptions?: FormLinesPaginationQuery$variables;
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
}

export const formLinesQuery = graphql`
  query FormLinesPaginationQuery(
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: FormsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...FormLines_data
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

const formLinesFragment = graphql`
  fragment FormLines_data on Query 
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "FormsOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters:{ type: "FilterGroup" }
  )
  @refetchable(queryName: "FormLinesRefetchQuery") {
    forms(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_forms") {
      edges {
        node {
          id
          ...FormLine_node
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

const FormLines: FunctionComponent<FormLinesProps> = ({
  setNumberOfElements,
  queryRef,
  dataColumns,
  paginationOptions,
}) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
  FormLinesPaginationQuery,
  FormLines_data$key>({
    queryRef,
    linesQuery: formLinesQuery,
    linesFragment: formLinesFragment,
    nodePath: ['forms', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });
  const forms = data?.forms?.edges ?? [];
  const globalCount = data?.forms?.pageInfo?.globalCount;
  return (
    <ListLinesContent
      initialLoading={!data}
      isLoading={isLoadingMore}
      loadMore={loadMore}
      hasMore={hasMore}
      dataList={forms}
      globalCount={globalCount ?? nbOfRowsToLoad}
      LineComponent={FormLineComponent}
      DummyLineComponent={FormLineDummy}
      dataColumns={dataColumns}
      nbOfRowsToLoad={nbOfRowsToLoad}
      paginationOptions={paginationOptions}
    />
  );
};

export default FormLines;
