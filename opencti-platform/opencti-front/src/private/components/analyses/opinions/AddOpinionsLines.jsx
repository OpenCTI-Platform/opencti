import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { graphql, createPaginationContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { CheckCircle, WorkOutline } from '@mui/icons-material';
import { ConnectionHandler } from 'relay-runtime';
import { truncate } from '../../../../utils/String';
import inject18n from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
import ItemMarkings from '../../../../components/ItemMarkings';

const styles = (theme) => ({
  avatar: {
    width: 24,
    height: 24,
  },
  icon: {
    color: theme.palette.primary.main,
  },
});

const opinionLinesMutationRelationAdd = graphql`
  mutation AddOpinionsLinesRelationAddMutation(
    $id: ID!
    $input: StixRefRelationshipAddInput!
  ) {
    opinionEdit(id: $id) {
      relationAdd(input: $input) {
        id
        from {
          ...OpinionLine_node
        }
      }
    }
  }
`;

export const opinionMutationRelationDelete = graphql`
  mutation AddOpinionsLinesRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    opinionEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        id
      }
    }
  }
`;

const sharedUpdater = (store, entityId, newEdge) => {
  const entity = store.get(entityId);
  const conn = ConnectionHandler.getConnection(entity, 'Pagination_opinions');
  ConnectionHandler.insertEdgeBefore(conn, newEdge);
};

class AddOpinionsLinesContainer extends Component {
  toggleOpinion(opinion) {
    const { entityId, entityOpinions } = this.props;
    const entityOpinionsIds = R.map((n) => n.node.id, entityOpinions);
    const alreadyAdded = entityOpinionsIds.includes(opinion.id);
    if (alreadyAdded) {
      const existingOpinion = R.head(
        R.filter((n) => n.node.id === opinion.id, entityOpinions),
      );
      commitMutation({
        mutation: opinionMutationRelationDelete,
        variables: {
          id: existingOpinion.node.id,
          toId: entityId,
          relationship_type: 'object',
        },
        updater: (store) => {
          const entity = store.get(entityId);
          const conn = ConnectionHandler.getConnection(
            entity,
            'Pagination_opinions',
          );
          ConnectionHandler.deleteNode(conn, opinion.id);
        },
      });
    } else {
      const input = {
        toId: entityId,
        relationship_type: 'object',
      };
      commitMutation({
        mutation: opinionLinesMutationRelationAdd,
        variables: {
          id: opinion.id,
          input,
        },
        updater: (store) => {
          const payload = store
            .getRootField('opinionEdit')
            .getLinkedRecord('relationAdd', { input });
          const relationId = payload.getValue('id');
          const node = payload.getLinkedRecord('from');
          const relation = store.get(relationId);
          payload.setLinkedRecord(node, 'node');
          payload.setLinkedRecord(relation, 'relation');
          sharedUpdater(store, entityId, payload);
        },
      });
    }
  }

  render() {
    const { classes, data, entityOpinions } = this.props;
    const entityOpinionsIds = R.map((n) => n.node.id, entityOpinions);
    return (
      <List>
        {data.opinions.edges.map((opinionNode) => {
          const opinion = opinionNode.node;
          const alreadyAdded = entityOpinionsIds.includes(opinion.id);
          const opinionId = opinion.external_id
            ? `(${opinion.external_id})`
            : '';
          return (
            <ListItem
              key={opinion.id}
              classes={{ root: classes.menuItem }}
              divider={true}
              button={true}
              onClick={this.toggleOpinion.bind(this, opinion)}
            >
              <ListItemIcon>
                {alreadyAdded ? (
                  <CheckCircle classes={{ root: classes.icon }} />
                ) : (
                  <WorkOutline />
                )}
              </ListItemIcon>
              <ListItemText
                primary={`${opinion.opinion} ${opinionId}`}
                secondary={truncate(opinion.explanation, 120)}
              />
              <div style={{ marginRight: 50 }}>
                {R.pathOr('', ['createdBy', 'name'], opinion)}
              </div>
              <div style={{ marginRight: 50 }}>
                <ItemMarkings
                  variant="inList"
                  markingDefinitions={opinion.objectMarking ?? []}
                  limit={1}
                />
              </div>
            </ListItem>
          );
        })}
      </List>
    );
  }
}

AddOpinionsLinesContainer.propTypes = {
  entityId: PropTypes.string,
  entityOpinions: PropTypes.array,
  data: PropTypes.object,
  limit: PropTypes.number,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

export const addOpinionsLinesQuery = graphql`
  query AddOpinionsLinesQuery($search: String, $count: Int, $cursor: ID) {
    ...AddOpinionsLines_data
      @arguments(search: $search, count: $count, cursor: $cursor)
  }
`;

const AddOpinionsLines = createPaginationContainer(
  AddOpinionsLinesContainer,
  {
    data: graphql`
      fragment AddOpinionsLines_data on Query
      @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
      ) {
        opinions(search: $search, first: $count, after: $cursor)
          @connection(key: "Pagination_opinions") {
          edges {
            node {
              id
              opinion
              explanation
            }
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
    getVariables(props, { count, cursor }) {
      return {
        count,
        cursor,
      };
    },
    query: addOpinionsLinesQuery,
  },
);

export default R.compose(inject18n, withStyles(styles))(AddOpinionsLines);
