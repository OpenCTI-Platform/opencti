import React, { FunctionComponent } from 'react';
import { graphql, usePaginationFragment } from 'react-relay';
import { CsvMapperLines_csvMapper$key } from '@components/data/csvMapper/__generated__/CsvMapperLines_csvMapper.graphql';
import CsvMapperLine from '@components/data/csvMapper/CsvMapperLine';
import LineDummy from '@components/common/LineDummy';
import { useCsvMappersData } from '@components/data/csvMapper/csvMappers.data';
import { csvMappers_MappersQuery, csvMappers_MappersQuery$variables } from '@components/data/csvMapper/__generated__/csvMappers_MappersQuery.graphql';
import { DataColumns } from '../../../../components/list_lines';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';

export const csvMapperLinesFragment = graphql`
  fragment CsvMapperLines_csvMapper on Query
  @argumentDefinitions(
    count: { type: "Int", defaultValue: 200 }
    after: { type: "ID" }
    orderBy: { type: "CsvMapperOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
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
  paginationOptions: csvMappers_MappersQuery$variables;
  dataColumns: DataColumns;
}

const CsvMapperLines: FunctionComponent<CsvMapperLinesProps> = ({
  paginationOptions,
  dataColumns,
}) => {
  const { csvMappers } = useCsvMappersData();
  const { data } = usePaginationFragment<
  csvMappers_MappersQuery,
  CsvMapperLines_csvMapper$key
  >(csvMapperLinesFragment, csvMappers);

  const csvMappersData = data?.csvMappers?.edges ?? [];
  const globalCount = data?.csvMappers?.pageInfo?.globalCount;

  return (
    <ListLinesContent
      initialLoading={false}
      loadMore={() => {}}
      hasMore={() => {}}
      isLoading={() => false}
      dataList={csvMappersData}
      globalCount={globalCount}
      LineComponent={CsvMapperLine}
      DummyLineComponent={LineDummy}
      dataColumns={dataColumns}
      paginationOptions={paginationOptions}
    />
  );
};

export default CsvMapperLines;
