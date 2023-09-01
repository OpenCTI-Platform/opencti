import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import {
  CsvMapperLines_csvMapper$key,
} from '@components/data/csvMapper/__generated__/CsvMapperLines_csvMapper.graphql';
import CsvMapperLine from '@components/data/csvMapper/CsvMapperLine';
import LineDummy from '@components/common/LineDummy';
import { DataColumns } from '../../../../components/list_lines';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import {
  CsvMapperLinesPaginationQuery,
  CsvMapperLinesPaginationQuery$variables,
} from './__generated__/CsvMapperLinesPaginationQuery.graphql';

export const csvMapperLinesQuery = graphql`
    query CsvMapperLinesPaginationQuery(
        $count: Int
        $orderBy: CsvMapperOrdering
        $orderMode: OrderingMode
        $filters: [CsvMapperFiltering!]
        $search: String
    ) {
        ...CsvMapperLines_csvMapper
        @arguments(
            count: $count
            orderBy: $orderBy
            orderMode: $orderMode
            filters: $filters
            search: $search
        )
    }
`;

export const csvMapperLinesFragment = graphql`
    fragment CsvMapperLines_csvMapper on Query
    @argumentDefinitions(
        count: { type: "Int", defaultValue: 200 }
        after: { type: "ID" }
        orderBy: { type: "CsvMapperOrdering", defaultValue: name }
        orderMode: { type: "OrderingMode", defaultValue: asc }
        filters: { type: "[CsvMapperFiltering!]" }
        search: { type: "String" }
    )
    @refetchable(queryName: "CsvMapperLines_DataQuery") {
        csvMappers(
            first: $count
            after: $after
            orderBy: $orderBy
            orderMode: $orderMode
            filters: $filters
            search: $search
        ) @connection(key: "Pagination_csvMappers") {
            edges {
                node {
                    ...CsvMapperLine_csvMapper
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

export interface CsvMapperLinesProps {
  queryRef: PreloadedQuery<CsvMapperLinesPaginationQuery>;
  paginationOptions: CsvMapperLinesPaginationQuery$variables;
  dataColumns: DataColumns;
}

const CsvMapperLines: FunctionComponent<CsvMapperLinesProps> = ({
  queryRef,
  paginationOptions,
  dataColumns,
}) => {
  const { data } = usePreloadedPaginationFragment<
  CsvMapperLinesPaginationQuery,
  CsvMapperLines_csvMapper$key
  >({
    queryRef,
    linesQuery: csvMapperLinesQuery,
    linesFragment: csvMapperLinesFragment,
    nodePath: ['csvMappers', 'pageInfo', 'globalCount'],
  });

  const csvMappers = data?.csvMappers?.edges ?? [];
  const globalCount = data?.csvMappers?.pageInfo?.globalCount;

  return (
      <ListLinesContent
          initialLoading={false}
          loadMore={() => {}}
          hasMore={() => {}}
          isLoading={() => false}
          dataList={csvMappers}
          globalCount={globalCount}
          LineComponent={CsvMapperLine}
          DummyLineComponent={LineDummy}
          dataColumns={dataColumns}
          paginationOptions={paginationOptions}
      />
  );
};

export default CsvMapperLines;
