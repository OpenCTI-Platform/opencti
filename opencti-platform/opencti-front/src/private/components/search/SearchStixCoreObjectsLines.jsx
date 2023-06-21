import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createPaginationContainer } from 'react-relay';
import { pathOr } from 'ramda';
import ListLinesContent from '../../../components/list_lines/ListLinesContent';
import {
  SearchStixCoreObjectLine,
  SearchStixCoreObjectLineDummy,
} from './SearchStixCoreObjectLine';
import { setNumberOfElements } from '../../../utils/Number';

const nbOfRowsToLoad = 50;

class SearchStixCoreObjectsLines extends Component {
  componentDidUpdate(prevProps) {
    setNumberOfElements(
      prevProps,
      this.props,
      'stixCoreObjects',
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
    } = this.props;
    return (
      <ListLinesContent
        initialLoading={initialLoading}
        loadMore={relay.loadMore.bind(this)}
        hasMore={relay.hasMore.bind(this)}
        isLoading={relay.isLoading.bind(this)}
        dataList={pathOr([], ['globalSearch', 'edges'], this.props.data)}
        globalCount={pathOr(
          nbOfRowsToLoad,
          ['globalSearch', 'pageInfo', 'globalCount'],
          this.props.data,
        )}
        LineComponent={<SearchStixCoreObjectLine />}
        DummyLineComponent={<SearchStixCoreObjectLineDummy />}
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

SearchStixCoreObjectsLines.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  dataColumns: PropTypes.object.isRequired,
  data: PropTypes.object,
  relay: PropTypes.object,
  stixCoreObjects: PropTypes.object,
  initialLoading: PropTypes.bool,
  onLabelClick: PropTypes.func,
  setNumberOfElements: PropTypes.func,
  onToggleEntity: PropTypes.func,
  selectedElements: PropTypes.object,
  deSelectedElements: PropTypes.object,
  selectAll: PropTypes.bool,
};

export const searchStixCoreObjectsLinesQuery = graphql`
  query SearchStixCoreObjectsLinesPaginationQuery(
    $types: [String]
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: StixCoreObjectsOrdering
    $orderMode: OrderingMode
    $filters: [StixCoreObjectsFiltering]
  ) {
    ...SearchStixCoreObjectsLines_data
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

export const searchStixCoreObjectsLinesSearchQuery = graphql`
  query SearchStixCoreObjectsLinesSearchQuery(
    $types: [String]
    $filters: [StixCoreObjectsFiltering]
    $search: String
  ) {
    stixCoreObjects(types: $types, search: $search, filters: $filters) {
      edges {
        node {
          id
          entity_type
          created_at
          updated_at
          ... on AttackPattern {
            name
            description
            aliases
          }
          ... on Campaign {
            name
            description
            aliases
          }
          ... on Note {
            attribute_abstract
            content
          }
          ... on ObservedData {
            name
            first_observed
            last_observed
          }
          ... on Opinion {
            opinion
            explanation
          }
          ... on Report {
            name
            description
          }
          ... on Grouping {
            name
            description
          }
          ... on CourseOfAction {
            name
            description
            x_opencti_aliases
          }
          ... on Individual {
            name
            description
            x_opencti_aliases
          }
          ... on Organization {
            name
            description
            x_opencti_aliases
          }
          ... on Sector {
            name
            description
            x_opencti_aliases
          }
          ... on System {
            name
            description
            x_opencti_aliases
          }
          ... on Indicator {
            name
            description
          }
          ... on Infrastructure {
            name
            description
          }
          ... on IntrusionSet {
            name
            aliases
            description
          }
          ... on Position {
            name
            description
            x_opencti_aliases
          }
          ... on City {
            name
            description
            x_opencti_aliases
          }
          ... on AdministrativeArea {
            name
            description
            x_opencti_aliases
          }
          ... on Country {
            name
            description
            x_opencti_aliases
          }
          ... on Region {
            name
            description
            x_opencti_aliases
          }
          ... on Malware {
            name
            aliases
            description
          }
          ... on ThreatActorGroup {
            name
            aliases
            description
          }
          ... on Tool {
            name
            aliases
            description
          }
          ... on Vulnerability {
            name
            description
          }
          ... on Incident {
            name
            aliases
            description
          }
          ... on Event {
            name
            aliases
            description
          }
          ... on Channel {
            name
            aliases
            description
          }
          ... on Narrative {
            name
            aliases
            description
          }
          ... on Language {
            name
            aliases
          }
          ... on DataComponent {
            name
          }
          ... on DataSource {
            name
          }
          ... on Case {
            name
          }
          ... on StixCyberObservable {
            observable_value
          }
          ... on IPv4Addr {
            countries {
              edges {
                node {
                  name
                  x_opencti_aliases
                }
              }
            }
          }
          ... on IPv6Addr {
            countries {
              edges {
                node {
                  name
                  x_opencti_aliases
                }
              }
            }
          }
          createdBy {
            ... on Identity {
              name
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
          objectLabel {
            edges {
              node {
                id
                value
                color
              }
            }
          }
          creators {
            id
            name
          }
          reports {
            pageInfo {
              globalCount
            }
          }
        }
      }
    }
  }
`;

export default createPaginationContainer(
  SearchStixCoreObjectsLines,
  {
    data: graphql`
      fragment SearchStixCoreObjectsLines_data on Query
      @argumentDefinitions(
        types: { type: "[String]" }
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
        orderBy: { type: "StixCoreObjectsOrdering", defaultValue: name }
        orderMode: { type: "OrderingMode", defaultValue: asc }
        filters: { type: "[StixCoreObjectsFiltering]" }
      ) {
        globalSearch(
          types: $types
          search: $search
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
          filters: $filters
        ) @connection(key: "Pagination_globalSearch") {
          edges {
            node {
              id
              entity_type
              created_at
              createdBy {
                ... on Identity {
                  name
                }
              }
              creators {
                id
                name
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
              ...SearchStixCoreObjectLine_node
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
      return props.data && props.data.stixCoreObjects;
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
    query: searchStixCoreObjectsLinesQuery,
  },
);
