import React, { FunctionComponent } from 'react';
import { graphql, usePaginationFragment } from 'react-relay';
import JsonMapperLine from '@components/data/jsonMapper/JsonMapperLine';
import LineDummy from '@components/common/LineDummy';
import { useJsonMappersData } from '@components/data/jsonMapper/jsonMappers.data';
import { jsonMappers_MappersQuery, jsonMappers_MappersQuery$variables } from '@components/data/jsonMapper/__generated__/jsonMappers_MappersQuery.graphql';
import { JsonMapperLines_jsonMapper$key } from '@components/data/jsonMapper/__generated__/JsonMapperLines_jsonMapper.graphql';
import { DataColumns } from '../../../../components/list_lines';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';

export const jsonMapperLinesFragment = graphql`
  fragment JsonMapperLines_jsonMapper on Query
  @argumentDefinitions(
    count: { type: "Int", defaultValue: 200 }
    after: { type: "ID" }
    orderBy: { type: "JsonMapperOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
    search: { type: "String" }
  )
  @refetchable(queryName: "JsonMapperLines_DataQuery") {
    jsonMappers(
      first: $count
      after: $after
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
      search: $search
    ) @connection(key: "Pagination_jsonMappers") {
      edges {
        node {
          ...JsonMapperLine_jsonMapper
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

export interface JsonMapperLinesProps {
  paginationOptions: jsonMappers_MappersQuery$variables;
  dataColumns: DataColumns;
}

const JsonMapperLines: FunctionComponent<JsonMapperLinesProps> = ({
  paginationOptions,
  dataColumns,
}) => {
  const { jsonMappers } = useJsonMappersData();
  const { data } = usePaginationFragment<
  jsonMappers_MappersQuery,
  JsonMapperLines_jsonMapper$key
  >(jsonMapperLinesFragment, jsonMappers);

  const jsonMappersData = data?.jsonMappers?.edges ?? [];
  const globalCount = data?.jsonMappers?.pageInfo?.globalCount;

  return (
    <ListLinesContent
      initialLoading={false}
      loadMore={() => {}}
      hasMore={() => {}}
      isLoading={() => false}
      dataList={jsonMappersData}
      globalCount={globalCount}
      LineComponent={JsonMapperLine}
      DummyLineComponent={LineDummy}
      dataColumns={dataColumns}
      paginationOptions={paginationOptions}
    />
  );
};

export default JsonMapperLines;
