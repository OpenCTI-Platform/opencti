import React from 'react';
import { graphql, createPaginationContainer } from 'react-relay';
import { pathOr } from 'ramda';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import StatusTemplateLine from './StatusTemplateLine';
import StatusTemplateLineDummy from './StatusTemplateLineDummy';

const nbOfRowsToLoad = 50;

const StatusTemplatesLines = ({ relay, paginationOptions, dataColumns, data, initialLoading }) => {
  return (
    <ListLinesContent
      initialLoading={initialLoading}
      loadMore={relay.loadMore}
      hasMore={relay.hasMore}
      isLoading={relay.isLoading}
      dataList={pathOr([], ['statusTemplates', 'edges'], data)}
      globalCount={pathOr(
        nbOfRowsToLoad,
        ['statusTemplates', 'pageInfo', 'globalCount'],
        data,
      )}
      LineComponent={<StatusTemplateLine />}
      DummyLineComponent={<StatusTemplateLineDummy />}
      dataColumns={dataColumns}
      nbOfRowsToLoad={nbOfRowsToLoad}
      paginationOptions={paginationOptions}
    />
  );
};

export const statusTemplatesLinesQuery = graphql`
    query StatusTemplatesLinesPaginationQuery(
        $search: String
        $count: Int!
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

export default createPaginationContainer(
  StatusTemplatesLines,
  {
    data: graphql`
        fragment StatusTemplatesLines_data on Query
        @argumentDefinitions(
            search: { type: "String" }
            count: { type: "Int", defaultValue: 25 }
            cursor: { type: "ID" }
            orderBy: { type: "StatusTemplateOrdering", defaultValue: name }
            orderMode: { type: "OrderingMode", defaultValue: asc }
        ) {
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
    `,
  },
  {
    direction: 'forward',
    getConnectionFromProps(props) {
      return props.data && props.data.statusTemplates;
    },
    getFragmentVariables(prevVars, totalCount) {
      return {
        ...prevVars,
        count: totalCount,
      };
    },
    getVariables(props, { count, cursor }, fragmentVariables) {
      return {
        search: fragmentVariables.search,
        count,
        cursor,
        orderBy: fragmentVariables.orderBy,
        orderMode: fragmentVariables.orderMode,
      };
    },
    query: statusTemplatesLinesQuery,
  },
);
