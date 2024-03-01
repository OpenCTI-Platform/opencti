import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createPaginationContainer } from 'react-relay';
import { map, filter, head, compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Avatar from '@mui/material/Avatar';
import { CheckCircle } from '@mui/icons-material';
import { ConnectionHandler } from 'relay-runtime';
import { truncate } from '../../../../utils/String';
import inject18n from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';

const styles = (theme) => ({
  avatar: {
    width: 24,
    height: 24,
  },
  icon: {
    color: theme.palette.primary.main,
  },
});

const groupingLinesMutationRelationAdd = graphql`
  mutation AddGroupingsLinesRelationAddMutation(
    $id: ID!
    $input: StixRefRelationshipAddInput!
  ) {
    groupingRelationAdd(id: $id, input: $input) {
      id
      to {
        ... on Grouping {
          id
          name
          description
          context
        }
      }
    }
  }
`;

export const groupingMutationRelationDelete = graphql`
  mutation AddGroupingsLinesRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    groupingRelationDelete(
      id: $id
      toId: $toId
      relationship_type: $relationship_type
    ) {
      id
    }
  }
`;

const sharedUpdater = (store, entityId, newEdge) => {
  const entity = store.get(entityId);
  const conn = ConnectionHandler.getConnection(entity, 'Pagination_groupings');
  ConnectionHandler.insertEdgeBefore(conn, newEdge);
};

class AddGroupingsLinesContainer extends Component {
  toggleGrouping(grouping) {
    const { entityId, entityGroupings } = this.props;
    const entityGroupingsIds = map((n) => n.node.id, entityGroupings);
    const alreadyAdded = entityGroupingsIds.includes(grouping.id);

    if (alreadyAdded) {
      const existingGrouping = head(
        filter((n) => n.node.id === grouping.id, entityGroupings),
      );
      commitMutation({
        mutation: groupingMutationRelationDelete,
        variables: {
          id: entityId,
          toId: existingGrouping.id,
          relationship_type: 'external-reference',
        },
        updater: (store) => {
          const entity = store.get(entityId);
          const conn = ConnectionHandler.getConnection(
            entity,
            'Pagination_groupings',
          );
          ConnectionHandler.deleteNode(conn, grouping.id);
        },
      });
    } else {
      const input = {
        fromId: entityId,
        relationship_type: 'external-reference',
      };
      commitMutation({
        mutation: groupingLinesMutationRelationAdd,
        variables: {
          id: grouping.id,
          input,
        },
        updater: (store) => {
          const payload = store.getLinkedRecord('groupingRelationAdd', {
            input,
          });
          const relationId = payload.getValue('id');
          const node = payload.getLinkedRecord('to');
          const relation = store.get(relationId);
          payload.setLinkedRecord(node, 'node');
          payload.setLinkedRecord(relation, 'relation');
          sharedUpdater(store, entityId, payload);
        },
      });
    }
  }

  render() {
    const { classes, data, entityGroupings } = this.props;
    const entityGroupingsIds = map((n) => n.node.id, entityGroupings);
    return (
      <List>
        {data.groupings.edges.map((groupingNode) => {
          const grouping = groupingNode.node;
          const alreadyAdded = entityGroupingsIds.includes(grouping.id);
          const groupingId = grouping.external_id
            ? `(${grouping.external_id})`
            : '';
          return (
            <ListItem
              key={grouping.id}
              classes={{ root: classes.menuItem }}
              divider={true}
              button={true}
              onClick={this.toggleGrouping.bind(this, grouping)}
            >
              <ListItemIcon>
                {alreadyAdded ? (
                  <CheckCircle classes={{ root: classes.icon }} />
                ) : (
                  <Avatar classes={{ root: classes.avatar }}>
                    {grouping.source_name.substring(0, 1)}
                  </Avatar>
                )}
              </ListItemIcon>
              <ListItemText
                primary={`${grouping.source_name} ${groupingId}`}
                secondary={truncate(
                  grouping.description !== null
                    && grouping.description.length > 0
                    ? grouping.description
                    : grouping.url,
                  120,
                )}
              />
            </ListItem>
          );
        })}
      </List>
    );
  }
}

AddGroupingsLinesContainer.propTypes = {
  entityId: PropTypes.string,
  entityGroupings: PropTypes.array,
  data: PropTypes.object,
  limit: PropTypes.number,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

export const addGroupingsLinesQuery = graphql`
  query AddGroupingsLinesQuery($search: String, $count: Int, $cursor: ID) {
    ...AddGroupingsLines_data
      @arguments(search: $search, count: $count, cursor: $cursor)
  }
`;

const AddGroupingsLines = createPaginationContainer(
  AddGroupingsLinesContainer,
  {
    data: graphql`
      fragment AddGroupingsLines_data on Query
      @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
      ) {
        groupings(search: $search, first: $count, after: $cursor)
          @connection(key: "Pagination_groupings") {
          edges {
            node {
              id
              name
              description
              context
            }
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
    getVariables(props, { count, cursor }) {
      return {
        count,
        cursor,
      };
    },
    query: addGroupingsLinesQuery,
  },
);

export default compose(inject18n, withStyles(styles))(AddGroupingsLines);
