import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { pathOr } from 'ramda';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import {
  CurationStixDomainEntityLine,
  CurationStixDomainEntityLineDummy,
} from './CurationStixDomainEntityLine';
import { setNumberOfElements } from '../../../../utils/Number';

const nbOfRowsToLoad = 25;

class CurationStixDomainEntitiesLines extends Component {
  componentDidUpdate(prevProps) {
    setNumberOfElements(
      prevProps,
      this.props,
      'stixDomainEntities',
      this.props.setNumberOfElements.bind(this),
    );
  }

  render() {
    const {
      initialLoading,
      dataColumns,
      relay,
      onTagClick,
      onToggleEntity,
      selectedElements,
    } = this.props;
    return (
      <ListLinesContent
        initialLoading={initialLoading}
        loadMore={relay.loadMore.bind(this)}
        hasMore={relay.hasMore.bind(this)}
        isLoading={relay.isLoading.bind(this)}
        dataList={pathOr([], ['stixDomainEntities', 'edges'], this.props.data)}
        globalCount={pathOr(
          nbOfRowsToLoad,
          ['stixDomainEntities', 'pageInfo', 'globalCount'],
          this.props.data,
        )}
        LineComponent={<CurationStixDomainEntityLine />}
        DummyLineComponent={<CurationStixDomainEntityLineDummy />}
        dataColumns={dataColumns}
        nbOfRowsToLoad={nbOfRowsToLoad}
        onTagClick={onTagClick.bind(this)}
        selectedElements={selectedElements}
        onToggleEntity={onToggleEntity.bind(this)}
      />
    );
  }
}

CurationStixDomainEntitiesLines.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  dataColumns: PropTypes.object.isRequired,
  data: PropTypes.object,
  relay: PropTypes.object,
  stixDomainEntities: PropTypes.object,
  initialLoading: PropTypes.bool,
  onTagClick: PropTypes.func,
  setNumberOfElements: PropTypes.func,
  onToggleEntity: PropTypes.func,
  selectedElements: PropTypes.object,
};

export const curationStixDomainEntitiesLinesQuery = graphql`
  query CurationStixDomainEntitiesLinesPaginationQuery(
    $types: [String]
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: StixDomainEntitiesOrdering
    $orderMode: OrderingMode
    $filters: [StixDomainEntitiesFiltering]
  ) {
    ...CurationStixDomainEntitiesLines_data
      @arguments(
        types: $types
        search: $search
        count: $count
        cursor: $cursor
        orderBy: $orderBy
        orderMode: $orderMode
        filters: $filters
      )
  }
`;

export const curationStixDomainEntitiesLinesSearchQuery = graphql`
  query CurationStixDomainEntitiesLinesSearchQuery($search: String) {
    stixDomainEntities(search: $search) {
      edges {
        node {
          id
          entity_type
          name
          created_at
          updated_at
          createdByRef {
            node {
              name
            }
          }
        }
      }
    }
  }
`;

export default createPaginationContainer(
  CurationStixDomainEntitiesLines,
  {
    data: graphql`
      fragment CurationStixDomainEntitiesLines_data on Query
        @argumentDefinitions(
          types: { type: "[String]" }
          search: { type: "String" }
          count: { type: "Int", defaultValue: 25 }
          cursor: { type: "ID" }
          orderBy: { type: "StixDomainEntitiesOrdering", defaultValue: "name" }
          orderMode: { type: "OrderingMode", defaultValue: "asc" }
          filters: { type: "[StixDomainEntitiesFiltering]" }
        ) {
        stixDomainEntities(
          types: $types
          search: $search
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
          filters: $filters
        ) @connection(key: "Pagination_stixDomainEntities") {
          edges {
            node {
              id
              entity_type
              name
              alias
              created_at
              createdByRef {
                node {
                  name
                }
              }
              markingDefinitions {
                edges {
                  node {
                    id
                    definition
                  }
                }
              }
              ...CurationStixDomainEntityLine_node
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
      return props.data && props.data.stixDomainEntities;
    },
    getFragmentVariables(prevVars, totalCount) {
      return {
        ...prevVars,
        count: totalCount,
      };
    },
    getVariables(props, { count, cursor }, fragmentVariables) {
      return {
        types: fragmentVariables.types,
        search: fragmentVariables.search,
        count,
        cursor,
        orderBy: fragmentVariables.orderBy,
        orderMode: fragmentVariables.orderMode,
        filters: fragmentVariables.filters,
      };
    },
    query: curationStixDomainEntitiesLinesQuery,
  },
);
