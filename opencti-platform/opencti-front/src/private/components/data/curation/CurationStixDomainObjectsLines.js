import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { pathOr } from 'ramda';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import {
  CurationStixDomainObjectLine,
  CurationStixDomainObjectLineDummy,
} from './CurationStixDomainObjectLine';
import { setNumberOfElements } from '../../../../utils/Number';

const nbOfRowsToLoad = 50;

class CurationStixDomainObjectsLines extends Component {
  componentDidUpdate(prevProps) {
    setNumberOfElements(
      prevProps,
      this.props,
      'stixDomainObjects',
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
    } = this.props;
    return (
      <ListLinesContent
        initialLoading={initialLoading}
        loadMore={relay.loadMore.bind(this)}
        hasMore={relay.hasMore.bind(this)}
        isLoading={relay.isLoading.bind(this)}
        dataList={pathOr([], ['stixDomainObjects', 'edges'], this.props.data)}
        globalCount={pathOr(
          nbOfRowsToLoad,
          ['stixDomainObjects', 'pageInfo', 'globalCount'],
          this.props.data,
        )}
        LineComponent={<CurationStixDomainObjectLine />}
        DummyLineComponent={<CurationStixDomainObjectLineDummy />}
        dataColumns={dataColumns}
        nbOfRowsToLoad={nbOfRowsToLoad}
        onLabelClick={onLabelClick.bind(this)}
        selectedElements={selectedElements}
        onToggleEntity={onToggleEntity.bind(this)}
      />
    );
  }
}

CurationStixDomainObjectsLines.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  dataColumns: PropTypes.object.isRequired,
  data: PropTypes.object,
  relay: PropTypes.object,
  stixDomainObjects: PropTypes.object,
  initialLoading: PropTypes.bool,
  onLabelClick: PropTypes.func,
  setNumberOfElements: PropTypes.func,
  onToggleEntity: PropTypes.func,
  selectedElements: PropTypes.object,
};

export const curationStixDomainObjectsLinesQuery = graphql`
  query CurationStixDomainObjectsLinesPaginationQuery(
    $types: [String]
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: StixDomainObjectsOrdering
    $orderMode: OrderingMode
    $filters: [StixDomainObjectsFiltering]
  ) {
    ...CurationStixDomainObjectsLines_data
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

export const curationStixDomainObjectsLinesSearchQuery = graphql`
  query CurationStixDomainObjectsLinesSearchQuery(
    $types: [String]
    $search: String
  ) {
    stixDomainObjects(types: $types, search: $search) {
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
          ... on ThreatActor {
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
          ... on XOpenCTIIncident {
            name
            aliases
            description
          }
          createdBy {
            ... on Identity {
              name
            }
          }
        }
      }
    }
  }
`;

export default createPaginationContainer(
  CurationStixDomainObjectsLines,
  {
    data: graphql`
      fragment CurationStixDomainObjectsLines_data on Query
      @argumentDefinitions(
        types: { type: "[String]" }
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
        orderBy: { type: "StixDomainObjectsOrdering", defaultValue: name }
        orderMode: { type: "OrderingMode", defaultValue: asc }
        filters: { type: "[StixDomainObjectsFiltering]" }
      ) {
        stixDomainObjects(
          types: $types
          search: $search
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
          filters: $filters
        ) @connection(key: "Pagination_stixDomainObjects") {
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
              objectMarking {
                edges {
                  node {
                    id
                    definition
                  }
                }
              }
              ...CurationStixDomainObjectLine_node
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
      return props.data && props.data.stixDomainObjects;
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
    query: curationStixDomainObjectsLinesQuery,
  },
);
