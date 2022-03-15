import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { interval } from 'rxjs';
import * as R from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import { createFragmentContainer } from 'react-relay';
import ListItem from '@material-ui/core/ListItem';
import ListItemText from '@material-ui/core/ListItemText';
import graphql from 'babel-plugin-relay/macro';
import inject18n from '../../../../../components/i18n';
import ListLinesContent from '../../../../../components/list_lines/ListLinesContent';
import {
  RemediationEntityLine,
  RemediationEntityLineDummy,
} from './RemediationEntityLine';
import { TEN_SECONDS } from '../../../../../utils/Time';

const styles = (theme) => ({
  paper: {
    listStyle: 'none',
    height: '100%',
    boxShadow: 'none',
  },
  ListItem: {
    width: '97%',
    display: 'grid',
    gridTemplateColumns: '19.7% 15% 15.5% 15% 1fr 1fr',
  },
  bodyItem: {
    height: 35,
    float: 'left',
    whiteSpace: 'nowrap',
  },
});

const interval$ = interval(TEN_SECONDS);

const nbOfRowsToLoad = 50;

class RemediationEntitiesLines extends Component {
  // componentDidMount() {
  //   this.subscription = interval$.subscribe(() => {
  //     this.props.relay.refetchConnection(25);
  //   });
  // }

  // componentWillUnmount() {
  //   this.subscription.unsubscribe();
  // }

  render() {
    const {
      initialLoading,
      dataColumns,
      relay,
      classes,
      t,
      data,
      entityLink,
      paginationOptions,
      displayRelation,
      entityId,
    } = this.props;
    const RemediationEntitiesLogEdges = R.pathOr([], ['risk', 'remediations'], data);
    return (
      // <ListLinesContent
      //   initialLoading={initialLoading}
      //   loadMore={relay.loadMore.bind(this)}
      //   hasMore={relay.hasMore.bind(this)}
      //   isLoading={relay.isLoading.bind(this)}
      //   dataList={pathOr(
      //     [],
      //     ['risk', 'remediations', 'edges'],
      //     this.props.data,
      //   )}
      //   globalCount={pathOr(
      //     nbOfRowsToLoad,
      //     ['risk', 'remediations', 'pageInfo', 'globalCount'],
      //     this.props.data,
      //   )}
      //   LineComponent={
      //     <RemediationEntityLine
      //       displayRelation={displayRelation}
      //       entityId={entityId}
      //     />
      //   }
      //   DummyLineComponent={
      //     <RemediationEntityLineDummy
      //       displayRelation={displayRelation}
      //     />
      //   }
      //   dataColumns={dataColumns}
      //   nbOfRowsToLoad={nbOfRowsToLoad}
      //   paginationOptions={paginationOptions}
      //   entityLink={entityLink}
      //   entityId={entityId}
      // />
      <Paper className={classes.paper}>
        <ListItem style={{ borderBottom: '2px solid white' }}>
          <ListItemText
            primary={<div className={classes.ListItem} >
              <div className={classes.bodyItem}>
                <Typography align="left" variant="button">
                  {t('Source')}
                </Typography>
              </div>
              <div className={classes.bodyItem}>
                <Typography align="left" variant="button">
                  {t('Name')}
                </Typography>
              </div>
              <div className={classes.bodyItem}>
                <Typography align="left" variant="button">
                  {t('Response Type')}
                </Typography>
              </div>
              <div className={classes.bodyItem}>
                <Typography align="left" variant="button">
                  {t('Lifecycle')}
                </Typography>
              </div>
              <div className={classes.bodyItem}>
                <Typography align="left" variant="button">
                  {t('Start Date')}
                </Typography>
              </div>
              <div className={classes.bodyItem}>
                <Typography align="left" variant="button">
                  {t('End Date')}
                </Typography>
              </div>
            </div>}
          />
        </ListItem>
        {(RemediationEntitiesLogEdges.length > 0 ? (RemediationEntitiesLogEdges.map(
          (remediationEdge, key) => <RemediationEntityLine
            node={remediationEdge}
            key={remediationEdge.id}
            entityId={entityId}
          />,
        )) : <>
          No Record Found </>)}
      </Paper>
    );
  }
}

RemediationEntitiesLines.propTypes = {
  classes: PropTypes.object,
  paginationOptions: PropTypes.object,
  dataColumns: PropTypes.object.isRequired,
  entityId: PropTypes.string,
  t: PropTypes.func,
  data: PropTypes.object,
  relay: PropTypes.object,
  stixCoreRelationships: PropTypes.object,
  initialLoading: PropTypes.bool,
  entityLink: PropTypes.string,
  displayRelation: PropTypes.bool,
};

const RemediationEntitiesLinesFragment = createFragmentContainer(
  RemediationEntitiesLines,
  {
    risk: graphql`
    fragment RemediationEntitiesLines_risk on Risk{
      id
      created
      modified
      ...RemediationEntityLine_node
    }
    `,
  },
);
// export const remediationEntitiesLinesQuery = graphql`
//   query RemediationEntitiesLinesQuery($id: ID!) {
//     # ...RemediationEntitiesLines_data
//     # @arguments(count: $count, id: $id)
//     risk(id: $id) {
//       id
//       #  remediations {
//       #    id
//       #    name
//       #    lifecycle
//       #    response_type
//       #    tasks(first: 1) {
//       #      edges {
//       #        node {
//       #          timing {
//       #            ... on DateRangeTiming {
//       #              start_date
//       #              end_date
//       #            }
//       #          }
//       #        }
//       #      }
//       #    }
//       #    relationships {
//       #      edges {
//       #        node {
//       #          source
//       #        }
//       #      }
//       #    }
//       #    external_references {
//       #      edges {
//       #        node {
//       #          source_name
//       #        }
//       #      }
//       #    }
//       #  }
//     }
//   }
// `;

export default R.compose(
  inject18n,
  withStyles(styles),
)(RemediationEntitiesLinesFragment);
// export default createFragmentContainer(
//   RemediationEntitiesLines,
//   {
//     data: graphql`
//       fragment RemediationEntitiesLines_data on Query
//       @argumentDefinitions(
//         count: { type: "Int", defaultValue: 25 }
//         id: { type: "ID!" }
//       ) {
//         risk(id: $id) {
//           id
//           # remediations {
//           #   id
//           #   name
//           #   lifecycle
//           #   response_type
//           #   tasks(first: 1) {
//           #     edges {
//           #       node {
//           #         timing {
//           #           ... on DateRangeTiming {
//           #             start_date
//           #             end_date
//           #           }
//           #         }
//           #       }
//           #     }
//           #   }
//           #   relationships {
//           #     edges {
//           #       node {
//           #         source
//           #       }
//           #     }
//           #   }
//           #   external_references {
//           #     edges {
//           #       node {
//           #         source_name
//           #       }
//           #     }
//           #   }
//           # }
//         }
//       }
//     `,
//   },
// {
//   direction: 'forward',
//   getConnectionFromProps(props) {
//     return props.data && props.data.risk.remediations;
//   },
//   getFragmentVariables(prevVars, totalCount) {
//     return {
//       ...prevVars,
//       count: totalCount,
//     };
//   },
//   getVariables(props, { count }, fragmentVariables) {
//     return {
//       count,
//       id: fragmentVariables.id,
//     };
//   },
//   query: remediationEntitiesLinesQuery,
// },
// );

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
