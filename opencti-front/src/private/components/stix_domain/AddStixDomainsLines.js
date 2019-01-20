import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { commitMutation, createPaginationContainer } from 'react-relay';
import { map, filter, head } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import Avatar from '@material-ui/core/Avatar';
import { CheckCircle } from '@material-ui/icons';
import graphql from 'babel-plugin-relay/macro';
import { ConnectionHandler } from 'relay-runtime';
import truncate from '../../../utils/String';
import inject18n from '../../../components/i18n';
import environment from '../../../relay/environment';

const styles = theme => ({
  itemIcon: {
    color: theme.palette.primary.main,
  },
  icon: {
    color: theme.palette.primary.main,
  },
});

const stixDomainLinesMutationRelationAdd = graphql`
    mutation AddStixDomainsLinesRelationAddMutation($id: ID!, $input: RelationAddInput!) {
        stixDomainEntityEdit(id: $id) {
            relationAdd(input: $input) {
                node {
                    ... on StixDomainEntity {
                        id
                        name
                    }
                }
                relation {
                    id
                }
            }
        }
    }
`;

export const stixDomainMutationRelationDelete = graphql`
    mutation AddStixDomainsLinesRelationDeleteMutation($id: ID!, $relationId: ID!) {
        stixDomainEntityEdit(id: $id) {
            relationDelete(relationId: $relationId) {
                node {
                    ... on StixDomainEntity {
                        id
                        name
                    }
                }
            }
        }
    }
`;

const sharedUpdater = (store, userId, paginationOptions, newEdge) => {
  const userProxy = store.get(userId);
  const conn = ConnectionHandler.getConnection(
    userProxy,
    'Pagination_stixDomainsOf',
    paginationOptions,
  );
  ConnectionHandler.insertEdgeBefore(conn, newEdge);
};

class AddStixDomainsLines extends Component {
  toggleStixDomain(stixDomain) {
    const { entityId, entityStixDomains, entityPaginationOptions } = this.props;
    const entityStixDomainsIds = map(n => n.node.id, entityStixDomains);
    const alreadyAdded = entityStixDomainsIds.includes(stixDomain.id);

    if (alreadyAdded) {
      const existingStixDomain = head(filter(n => n.node.id === stixDomain.id, entityStixDomains));
      commitMutation(environment, {
        mutation: stixDomainMutationRelationDelete,
        variables: {
          id: stixDomain.id,
          relationId: existingStixDomain.relation.id,
        },
        updater: (store) => {
          const container = store.getRoot();
          const userProxy = store.get(container.getDataID());
          const conn = ConnectionHandler.getConnection(
            userProxy,
            'Pagination_stixDomainsOf',
            entityPaginationOptions,
          );
          ConnectionHandler.deleteNode(conn, stixDomain.id);
        },
      });
    } else {
      const input = {
        fromRole: 'so',
        toId: stixDomain.id,
        toRole: 'external_reference',
        through: 'external_references',
      };
      commitMutation(environment, {
        mutation: stixDomainLinesMutationRelationAdd,
        variables: {
          id: entityId,
          input,
        },
        updater: (store) => {
          const payload = store.getRootField('stixDomainEdit').getLinkedRecord('relationAdd', { input });
          const container = store.getRoot();
          sharedUpdater(store, container.getDataID(), entityPaginationOptions, payload);
        },
      });
    }
  }

  render() {
    const {
      classes, data, entityStixDomains,
    } = this.props;
    const entityStixDomainsIds = map(n => n.node.id, entityStixDomains);
    return (
      <List>
        {data.stixDomains.edges.map((stixDomainNode) => {
          const stixDomain = stixDomainNode.node;
          const alreadyAdded = entityStixDomainsIds.includes(stixDomain.id);
          const stixDomainId = stixDomain.external_id ? `(${stixDomain.external_id})` : '';
          return (
            <ListItem
              key={stixDomain.id}
              classes={{ root: classes.menuItem }}
              divider={true}
              button={true}
              onClick={this.toggleStixDomain.bind(this, stixDomain)}
            >
              <ListItemIcon>
                {alreadyAdded ? <CheckCircle classes={{ root: classes.icon }}/> : <Avatar classes={{ root: classes.avatar }}>{stixDomain.source_name.substring(0, 1)}</Avatar>}
              </ListItemIcon>
              <ListItemText
                primary={`${stixDomain.source_name} ${stixDomainId}`}
                secondary={truncate(stixDomain.description !== null && stixDomain.description.length > 0 ? stixDomain.description : stixDomain.url, 120)}
              />
            </ListItem>
          );
        })}
      </List>
    );
  }
}

AddStixDomainsLines.propTypes = {
  entityId: PropTypes.string,
  entityStixDomains: PropTypes.array,
  entityPaginationOptions: PropTypes.object,
  data: PropTypes.object,
  limit: PropTypes.number,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

export const addStixDomainsLinesQuery = graphql`
    query AddStixDomainsLinesQuery($search: String, $count: Int!, $cursor: ID, $orderBy: StixDomainEntitiesOrdering, $orderMode: OrderingMode) {
        ...AddStixDomainsLines_data @arguments(search: $search, count: $count, cursor: $cursor, orderBy: $orderBy, orderMode: $orderMode)
    }
`;

export default inject18n(withStyles(styles)(createPaginationContainer(
  AddStixDomainsLines,
  {
    data: graphql`
        fragment AddStixDomainsLines_data on Query @argumentDefinitions(
            search: {type: "String"}
            count: {type: "Int", defaultValue: 25}
            cursor: {type: "ID"}
            orderBy: {type: "StixDomainEntitiesOrdering", defaultValue: ID}
            orderMode: {type: "OrderingMode", defaultValue: "asc"}
        ) {
            stixDomainEntities(search: $search, first: $count, after: $cursor, orderBy: $orderBy, orderMode: $orderMode) @connection(key: "Pagination_stixDomainEntities") {
                edges {
                    node {
                        id
                        type
                        name
                        description
                    }
                }
            }
        }
    `,
  },
  {
    direction: 'forward',
    getConnectionFromProps(props) {
      return props.data && props.data.stixDomains;
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
        orderBy: fragmentVariables.orderBy,
        orderMode: fragmentVariables.orderMode,
      };
    },
    query: addStixDomainsLinesQuery,
  },
)));
