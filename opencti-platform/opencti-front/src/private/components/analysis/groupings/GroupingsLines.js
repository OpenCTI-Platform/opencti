import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer, graphql } from 'react-relay';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { GroupingLine, GroupingLineDummy } from './GroupingLine';
import { setNumberOfElements } from '../../../../utils/Number';

const nbOfRowsToLoad = 50;

class GroupingsLines extends Component {
  componentDidUpdate(prevProps) {
    setNumberOfElements(
      prevProps,
      this.props,
      'groupings',
      this.props.setNumberOfElements.bind(this),
    );
  }

  render() {
    const {
      initialLoading,
      dataColumns,
      relay,
      onLabelClick,
      onToggleEntity,
      selectedElements,
      deSelectedElements,
      selectAll,
      data,
    } = this.props;

    return (
      <ListLinesContent
        initialLoading={initialLoading}
        loadMore={relay.loadMore.bind(this)}
        hasMore={relay.hasMore.bind(this)}
        isLoading={relay.isLoading.bind(this)}
        dataList={data?.groupings?.edges ?? []}
        globalCount={data?.groupings?.pageInfo?.globalCount ?? nbOfRowsToLoad}
        LineComponent={<GroupingLine />}
        DummyLineComponent={<GroupingLineDummy />}
        dataColumns={dataColumns}
        nbOfRowsToLoad={nbOfRowsToLoad}
        onLabelClick={onLabelClick.bind(this)}
        selectedElements={selectedElements}
        deSelectedElements={deSelectedElements}
        selectAll={selectAll}
        onToggleEntity={onToggleEntity.bind(this)}
      />
    );
  }
}

GroupingsLines.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  dataColumns: PropTypes.object.isRequired,
  data: PropTypes.object,
  relay: PropTypes.object,
  groupings: PropTypes.object,
  initialLoading: PropTypes.bool,
  searchTerm: PropTypes.string,
  onLabelClick: PropTypes.func,
  setNumberOfElements: PropTypes.func,
  onToggleEntity: PropTypes.func,
  selectedElements: PropTypes.object,
  deSelectedElements: PropTypes.object,
  selectAll: PropTypes.bool,
};

export const groupingsLinesQuery = graphql`
  query GroupingsLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: GroupingsOrdering
    $orderMode: OrderingMode
    $filters: [GroupingsFiltering!]
  ) {
    ...GroupingsLines_data
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
  GroupingsLines,
  {
    data: graphql`
      fragment GroupingsLines_data on Query
      @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
        orderBy: { type: "GroupingsOrdering", defaultValue: name }
        orderMode: { type: "OrderingMode", defaultValue: asc }
        filters: { type: "[GroupingsFiltering!]" }
      ) {
        groupings(
          search: $search
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
          filters: $filters
        ) @connection(key: "Pagination_groupings") {
          edges {
            node {
              id
              name
              context
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
                    definition_type
                    definition
                    x_opencti_order
                    x_opencti_color
                  }
                }
              }
              ...GroupingLine_node
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
      return props.data && props.data.groupings;
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
    query: groupingsLinesQuery,
  },
);
