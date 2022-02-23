import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createPaginationContainer } from 'react-relay';
import { pathOr } from 'ramda';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { OpinionLine, OpinionLineDummy } from './OpinionLine';
import { setNumberOfElements } from '../../../../utils/Number';

const nbOfRowsToLoad = 50;

class OpinionsLines extends Component {
  componentDidUpdate(prevProps) {
    setNumberOfElements(
      prevProps,
      this.props,
      'opinions',
      this.props.setNumberOfElements.bind(this),
    );
  }

  render() {
    const { initialLoading, dataColumns, relay, onLabelClick } = this.props;
    return (
      <ListLinesContent
        initialLoading={initialLoading}
        loadMore={relay.loadMore.bind(this)}
        hasMore={relay.hasMore.bind(this)}
        isLoading={relay.isLoading.bind(this)}
        dataList={pathOr([], ['opinions', 'edges'], this.props.data)}
        globalCount={pathOr(
          nbOfRowsToLoad,
          ['opinions', 'pageInfo', 'globalCount'],
          this.props.data,
        )}
        LineComponent={<OpinionLine />}
        DummyLineComponent={<OpinionLineDummy />}
        dataColumns={dataColumns}
        nbOfRowsToLoad={nbOfRowsToLoad}
        onLabelClick={onLabelClick.bind(this)}
      />
    );
  }
}

OpinionsLines.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  dataColumns: PropTypes.object.isRequired,
  data: PropTypes.object,
  relay: PropTypes.object,
  opinions: PropTypes.object,
  initialLoading: PropTypes.bool,
  searchTerm: PropTypes.string,
  onLabelClick: PropTypes.func,
  setNumberOfElements: PropTypes.func,
};

export const opinionsLinesQuery = graphql`
  query OpinionsLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: OpinionsOrdering
    $orderMode: OrderingMode
    $filters: [OpinionsFiltering]
  ) {
    ...OpinionsLines_data
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

export default createPaginationContainer(
  OpinionsLines,
  {
    data: graphql`
      fragment OpinionsLines_data on Query
      @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
        orderBy: { type: "OpinionsOrdering", defaultValue: created }
        orderMode: { type: "OrderingMode", defaultValue: desc }
        filters: { type: "[OpinionsFiltering]" }
      ) {
        opinions(
          search: $search
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
          filters: $filters
        ) @connection(key: "Pagination_opinions") {
          edges {
            node {
              id
              opinion
              explanation
              created
              createdBy {
                ... on Identity {
                  id
                  name
                  entity_type
                }
              }
              objectMarking {
                edges {
                  node {
                    id
                    definition
                  }
                }
              }
              ...OpinionLine_node
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
      return props.data && props.data.opinions;
    },
    getFragmentVariables(prevVars, totalCount) {
      return {
        ...prevVars,
        count: totalCount,
      };
    },
    getVariables(props, { count, cursor }, fragmentVariables) {
      return {
        count,
        cursor,
        search: fragmentVariables.search,
        orderBy: fragmentVariables.orderBy,
        orderMode: fragmentVariables.orderMode,
        filters: fragmentVariables.filters,
      };
    },
    query: opinionsLinesQuery,
  },
);
