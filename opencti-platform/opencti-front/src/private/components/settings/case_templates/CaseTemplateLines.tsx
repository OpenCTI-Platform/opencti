import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';
import { DataColumns } from '../../../../components/list_lines';
import { CaseTemplateLinesPaginationQuery, CaseTemplateLinesPaginationQuery$variables } from './__generated__/CaseTemplateLinesPaginationQuery.graphql';
import { CaseTemplateLines_data$key } from './__generated__/CaseTemplateLines_data.graphql';
import CaseTemplateLine from './CaseTemplateLine';
import CaseTemplateLineDummy from './CaseTemplateLineDummy';

const nbOfRowsToLoad = 50;

interface CaseTemplatesLinesProps {
  queryRef: PreloadedQuery<CaseTemplateLinesPaginationQuery>;
  dataColumns: DataColumns;
  paginationOptions: CaseTemplateLinesPaginationQuery$variables;
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
}

export const caseTemplatesLinesQuery = graphql`
  query CaseTemplateLinesPaginationQuery(
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: CaseTemplatesOrdering
    $orderMode: OrderingMode
  ) {
    ...CaseTemplateLines_data
    @arguments(
      search: $search
      count: $count
      cursor: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
    )
  }
`;

const caseTemplatesLinesFragment = graphql`
  fragment CaseTemplateLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "CaseTemplatesOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
  )
  @refetchable(queryName: "CaseTemplatesLinesRefetchQuery") {
    caseTemplates(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
    ) @connection(key: "Pagination_caseTemplates") {
      edges {
        node {
          ...CaseTemplateLine_node
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

const CaseTemplateLines: FunctionComponent<CaseTemplatesLinesProps> = ({
  queryRef,
  dataColumns,
  paginationOptions,
  setNumberOfElements,
}) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
  CaseTemplateLinesPaginationQuery,
  CaseTemplateLines_data$key
  >({
    linesQuery: caseTemplatesLinesQuery,
    linesFragment: caseTemplatesLinesFragment,
    queryRef,
    nodePath: ['caseTemplates', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });

  return (
    <ListLinesContent
      initialLoading={!data}
      loadMore={loadMore}
      hasMore={hasMore}
      isLoading={isLoadingMore}
      dataList={data?.caseTemplates?.edges ?? []}
      globalCount={
        data?.caseTemplates?.pageInfo?.globalCount ?? nbOfRowsToLoad
      }
      LineComponent={CaseTemplateLine}
      DummyLineComponent={CaseTemplateLineDummy}
      dataColumns={dataColumns}
      nbOfRowsToLoad={nbOfRowsToLoad}
      paginationOptions={paginationOptions}
    />
  );
};

export default CaseTemplateLines;
