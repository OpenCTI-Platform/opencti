import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { interval } from 'rxjs';
import { pathOr } from 'ramda';
import { createPaginationContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import ListLinesContent from '../../../../../components/list_lines/ListLinesContent';
import {
  RemediationEntityLine,
  RemediationEntityLineDummy,
} from './RemediationEntityLine';
import { TEN_SECONDS } from '../../../../../utils/Time';

const interval$ = interval(TEN_SECONDS);

const nbOfRowsToLoad = 50;

class RemediationEntitiesLines extends Component {
  componentDidMount() {
    this.subscription = interval$.subscribe(() => {
      this.props.relay.refetchConnection(25);
    });
  }

  componentWillUnmount() {
    this.subscription.unsubscribe();
  }

  render() {
    const {
      initialLoading,
      dataColumns,
      relay,
      entityLink,
      paginationOptions,
      displayRelation,
      entityId,
    } = this.props;
    console.log('RemediationEntitiesLinesData', this.props.data);
    return (
      <ListLinesContent
        initialLoading={initialLoading}
        loadMore={relay.loadMore.bind(this)}
        hasMore={relay.hasMore.bind(this)}
        isLoading={relay.isLoading.bind(this)}
        dataList={pathOr(
          [],
          ['risk', 'remediations', 'edges'],
          this.props.data,
        )}
        globalCount={pathOr(
          nbOfRowsToLoad,
          ['risk', 'remediations', 'pageInfo', 'globalCount'],
          this.props.data,
        )}
        LineComponent={
          <RemediationEntityLine
            displayRelation={displayRelation}
            entityId={entityId}
          />
        }
        DummyLineComponent={
          <RemediationEntityLineDummy
            displayRelation={displayRelation}
          />
        }
        dataColumns={dataColumns}
        nbOfRowsToLoad={nbOfRowsToLoad}
        paginationOptions={paginationOptions}
        entityLink={entityLink}
        entityId={entityId}
      />
    );
  }
}

RemediationEntitiesLines.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  dataColumns: PropTypes.object.isRequired,
  entityId: PropTypes.string,
  data: PropTypes.object,
  relay: PropTypes.object,
  stixCoreRelationships: PropTypes.object,
  initialLoading: PropTypes.bool,
  entityLink: PropTypes.string,
  displayRelation: PropTypes.bool,
};

export const remediationEntitiesLinesQuery = graphql`
  query RemediationEntitiesLinesQuery($count: Int!, $id: ID!) {
    ...RemediationEntitiesLines_data
      @arguments(count: $count, id: $id)
  }
`;

export default createPaginationContainer(
  RemediationEntitiesLines,
  {
    data: graphql`
      fragment RemediationEntitiesLines_data on Query
      @argumentDefinitions(
        count: { type: "Int", defaultValue: 25 }
        id: { type: "ID!" }
      ) {
        risk(id: $id) {
          id
          remediations(first: $count)
            @connection(key: "Pagination_remediations") {
            edges {
              node {
                id
                name
                lifecycle
                response_type
                tasks(first: 1) {
                  edges {
                    node {
                      timing {
                        ... on DateRangeTiming {
                          start_date
                          end_date
                        }
                      }
                    }
                  }
                }
                relationships {
                  edges {
                    node {
                      source
                    }
                  }
                }
                external_references {
                  edges {
                    node {
                      source_name
                    }
                  }
                }
              }
            }
          }
        }
      }
    `,
  },
  {
    direction: 'forward',
    getConnectionFromProps(props) {
      return props.data && props.data.risk.remediations;
    },
    getFragmentVariables(prevVars, totalCount) {
      return {
        ...prevVars,
        count: totalCount,
      };
    },
    getVariables(props, { count }, fragmentVariables) {
      return {
        count,
        id: fragmentVariables.id,
      };
    },
    query: remediationEntitiesLinesQuery,
  },
);

// export const RemediationEntitiesLinesQuery = graphql`
//   query RemediationEntitiesLinesQuery(
//     $elementId: String
//     $relationship_type: [String]
//     $toTypes: [String]
//     $startTimeStart: DateTime
//     $startTimeStop: DateTime
//     $stopTimeStart: DateTime
//     $stopTimeStop: DateTime
//     $confidences: [Int]
//     $search: String
//     $count: Int!
//     $cursor: ID
//     $orderBy: StixCoreRelationshipsOrdering
//     $orderMode: OrderingMode
//   ) {
//     ...StixCyberObservableEntitiesLines_data
//       @arguments(
//         elementId: $elementId
//         relationship_type: $relationship_type
//         toTypes: $toTypes
//         startTimeStart: $startTimeStart
//         startTimeStop: $startTimeStop
//         stopTimeStart: $stopTimeStart
//         stopTimeStop: $stopTimeStop
//         confidences: $confidences
//         search: $search
//         count: $count
//         cursor: $cursor
//         orderBy: $orderBy
//         orderMode: $orderMode
//       )
//   }
// `;

// export default createPaginationContainer(
//   RemediationEntitiesLines,
//   {
//     data: graphql`
//       fragment RemediationEntitiesLines_data on Query
//       @argumentDefinitions(
//         elementId: { type: "String" }
//         relationship_type: { type: "[String]" }
//         toTypes: { type: "[String]" }
//         startTimeStart: { type: "DateTime" }
//         startTimeStop: { type: "DateTime" }
//         stopTimeStart: { type: "DateTime" }
//         stopTimeStop: { type: "DateTime" }
//         confidences: { type: "[Int]" }
//         search: { type: "String" }
//         count: { type: "Int", defaultValue: 25 }
//         cursor: { type: "ID" }
//         orderBy: {
//           type: "StixCoreRelationshipsOrdering"
//           defaultValue: start_time
//         }
//         orderMode: { type: "OrderingMode" }
//       ) {
//         stixCoreRelationships(
//           elementId: $elementId
//           relationship_type: $relationship_type
//           toTypes: $toTypes
//           startTimeStart: $startTimeStart
//           startTimeStop: $startTimeStop
//           stopTimeStart: $stopTimeStart
//           stopTimeStop: $stopTimeStop
//           confidences: $confidences
//           search: $search
//           first: $count
//           after: $cursor
//           orderBy: $orderBy
//           orderMode: $orderMode
//         ) @connection(key: "Pagination_stixCoreRelationships") {
//           edges {
//             node {
//               ...RemediationEntityLine_node
//             }
//           }
//           pageInfo {
//             endCursor
//             hasNextPage
//             globalCount
//           }
//         }
//       }
//     `,
//   },
//   {
//     direction: 'forward',
//     getConnectionFromProps(props) {
//       return props.data && props.data.stixCoreRelationships;
//     },
//     getFragmentVariables(prevVars, totalCount) {
//       return {
//         ...prevVars,
//         count: totalCount,
//       };
//     },
//     getVariables(props, { count, cursor }, fragmentVariables) {
//       return {
//         elementId: fragmentVariables.elementId,
//         toTypes: fragmentVariables.toTypes,
//         relationship_type: fragmentVariables.relationship_type,
//         startTimeStart: fragmentVariables.startTimeStart,
//         startTimeStop: fragmentVariables.startTimeStop,
//         stopTimeStart: fragmentVariables.stopTimeStart,
//         stopTimeStop: fragmentVariables.stopTimeStop,
//         confidences: fragmentVariables.confidences,
//         search: fragmentVariables.search,
//         count,
//         cursor,
//         orderBy: fragmentVariables.orderBy,
//         orderMode: fragmentVariables.orderMode,
//       };
//     },
//     query: RemediationEntitiesLinesQuery,
//   },
// );
