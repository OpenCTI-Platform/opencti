import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createPaginationContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import { compose } from 'ramda';
import List from '@mui/material/List';
import { SimpleStixObjectOrStixRelationshipStixCoreRelationshipLine } from './SimpleStixObjectOrStixRelationshipStixCoreRelationshipLine';
import inject18n from '../../../../components/i18n';

const styles = (theme) => ({
  paper: {
    minHeight: 280,
    height: '100%',
    margin: '10px 0 0 0',
    borderRadius: 4,
  },
  avatar: {
    width: 24,
    height: 24,
    backgroundColor: theme.palette.primary.main,
  },
  avatarDisabled: {
    width: 24,
    height: 24,
  },
  placeholder: {
    display: 'inline-block',
    height: '1em',
    backgroundColor: theme.palette.grey[700],
  },
});

class SimpleStixObjectOrStixRelationshipStixCoreRelationshipsLinesContainer extends Component {
  render() {
    const {
      data,
      dataColumns,
      stixObjectOrStixRelationshipId,
      stixObjectOrStixRelationshipLink,
      paginationOptions,
      t,
    } = this.props;
    return (
      <div style={{ height: '100%' }}>
        {data.stixCoreRelationships.edges.length > 0 ? (
          <List>
            {data.stixCoreRelationships.edges.map(
              (stixCoreRelationshipEdge, index) => {
                const stixCoreRelationship = stixCoreRelationshipEdge.node;
                return (
                  <SimpleStixObjectOrStixRelationshipStixCoreRelationshipLine
                    key={`${stixObjectOrStixRelationshipId}_${index}`}
                    dataColumns={dataColumns}
                    entityId={stixObjectOrStixRelationshipId}
                    entityLink={stixObjectOrStixRelationshipLink}
                    paginationOptions={paginationOptions}
                    node={stixCoreRelationship}
                    connectionKey="Pagination_stixCoreRelationships"
                  />
                );
              },
            )}
          </List>
        ) : (
          <div
            style={{
              display: 'table',
              height: '100%',
              width: '100%',
              paddingTop: 15,
              paddingBottom: 15,
            }}
          >
            <span
              style={{
                display: 'table-cell',
                verticalAlign: 'middle',
                textAlign: 'center',
              }}
            >
              {t('No entities of this type has been found.')}
            </span>
          </div>
        )}
      </div>
    );
  }
}

SimpleStixObjectOrStixRelationshipStixCoreRelationshipsLinesContainer.propTypes = {
  stixObjectOrStixRelationshipId: PropTypes.string,
  stixObjectOrStixRelationshipLink: PropTypes.string,
  paginationOptions: PropTypes.object,
  data: PropTypes.object,
  limit: PropTypes.number,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

export const simpleStixObjectOrStixRelationshipStixCoreRelationshipsLinesQuery = graphql`
  query SimpleStixObjectOrStixRelationshipStixCoreRelationshipsLinesPaginationQuery(
    $fromOrToId: [String]!
    $relationship_type: [String]
    $startTimeStart: DateTime
    $startTimeStop: DateTime
    $stopTimeStart: DateTime
    $stopTimeStop: DateTime
    $confidences: [Int]
    $orderBy: StixCoreRelationshipsOrdering
    $orderMode: OrderingMode
    $count: Int
    $cursor: ID
  ) {
    ...SimpleStixObjectOrStixRelationshipStixCoreRelationshipsLines_data
      @arguments(
        fromOrToId: $fromOrToId
        relationship_type: $relationship_type
        startTimeStart: $startTimeStart
        startTimeStop: $startTimeStop
        stopTimeStart: $stopTimeStart
        stopTimeStop: $stopTimeStop
        confidences: $confidences
        orderBy: $orderBy
        orderMode: $orderMode
        count: $count
        cursor: $cursor
      )
  }
`;

const SimpleStixObjectOrStixRelationshipStixCoreRelationshipsLines = createPaginationContainer(
  SimpleStixObjectOrStixRelationshipStixCoreRelationshipsLinesContainer,
  {
    data: graphql`
        fragment SimpleStixObjectOrStixRelationshipStixCoreRelationshipsLines_data on Query
        @argumentDefinitions(
          fromOrToId: { type: "[String]!" }
          relationship_type: { type: "[String]" }
          startTimeStart: { type: "DateTime" }
          startTimeStop: { type: "DateTime" }
          stopTimeStart: { type: "DateTime" }
          stopTimeStop: { type: "DateTime" }
          confidences: { type: "[Int]" }
          orderBy: {
            type: "StixCoreRelationshipsOrdering"
            defaultValue: created_at
          }
          orderMode: { type: "OrderingMode", defaultValue: desc }
          count: { type: "Int", defaultValue: 25 }
          cursor: { type: "ID" }
        ) {
          stixCoreRelationships(
            fromOrToId: $fromOrToId
            relationship_type: $relationship_type
            startTimeStart: $startTimeStart
            startTimeStop: $startTimeStop
            stopTimeStart: $stopTimeStart
            stopTimeStop: $stopTimeStop
            confidences: $confidences
            orderBy: $orderBy
            orderMode: $orderMode
            first: $count
            after: $cursor
          ) @connection(key: "Pagination_stixCoreRelationships") {
            edges {
              node {
                ...SimpleStixObjectOrStixRelationshipStixCoreRelationshipLine_node
              }
            }
          }
        }
      `,
  },
  {
    direction: 'forward',
    getConnectionFromProps(props) {
      return props.data && props.data.stixCoreRelationships;
    },
    getFragmentVariables(prevVars, totalCount) {
      return {
        ...prevVars,
        count: totalCount,
      };
    },
    getVariables(props, { count, cursor }, fragmentVariables) {
      return {
        fromOrToId: fragmentVariables.fromOrToId,
        relationship_type: fragmentVariables.relationship_type,
        startTimeStart: fragmentVariables.startTimeStart,
        startTimeStop: fragmentVariables.startTimeStop,
        stopTimeStart: fragmentVariables.stopTimeStart,
        stopTimeStop: fragmentVariables.stopTimeStop,
        confidences: fragmentVariables.confidences,
        orderBy: fragmentVariables.orderBy,
        orderMode: fragmentVariables.orderMode,
        count,
        cursor,
      };
    },
    query: simpleStixObjectOrStixRelationshipStixCoreRelationshipsLinesQuery,
  },
);

export default compose(
  inject18n,
  withStyles(styles),
)(SimpleStixObjectOrStixRelationshipStixCoreRelationshipsLines);
