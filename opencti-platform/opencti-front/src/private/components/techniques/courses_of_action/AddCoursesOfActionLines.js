import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer } from 'react-relay';
import {
  map, filter, head, compose,
} from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import Avatar from '@material-ui/core/Avatar';
import { CheckCircle } from '@material-ui/icons';
import graphql from 'babel-plugin-relay/macro';
import { ConnectionHandler } from 'relay-runtime';
import { truncate } from '../../../../utils/String';
import inject18n from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';

const styles = theme => ({
  avatar: {
    width: 24,
    height: 24,
  },
  icon: {
    color: theme.palette.primary.main,
  },
});

const courseOfActionLinesMutationRelationAdd = graphql`
  mutation AddCoursesOfActionLinesRelationAddMutation(
    $id: ID!
    $input: RelationAddInput!
  ) {
    courseOfActionEdit(id: $id) {
      relationAdd(input: $input) {
        node {
          ... on CourseOfAction {
            id
            name
            description
          }
        }
        relation {
          id
        }
      }
    }
  }
`;

export const courseOfActionMutationRelationDelete = graphql`
  mutation AddCoursesOfActionLinesRelationDeleteMutation(
    $id: ID!
    $relationId: ID!
  ) {
    courseOfActionEdit(id: $id) {
      relationDelete(relationId: $relationId) {
        node {
          ... on CourseOfAction {
            id
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
    'Pagination_coursesOfAction',
    paginationOptions,
  );
  ConnectionHandler.insertEdgeBefore(conn, newEdge);
};

class AddCoursesOfActionLinesContainer extends Component {
  toggleCourseOfAction(courseOfAction) {
    const {
      entityId,
      entityCoursesOfAction,
      entityPaginationOptions,
    } = this.props;
    const entityCoursesOfActionIds = map(n => n.node.id, entityCoursesOfAction);
    const alreadyAdded = entityCoursesOfActionIds.includes(courseOfAction.id);

    if (alreadyAdded) {
      const existingCourseOfAction = head(
        filter(n => n.node.id === courseOfAction.id, entityCoursesOfAction),
      );
      commitMutation({
        mutation: courseOfActionMutationRelationDelete,
        variables: {
          id: courseOfAction.id,
          relationId: existingCourseOfAction.relation.id,
        },
        updater: (store) => {
          const container = store.getRoot();
          const userProxy = store.get(container.getDataID());
          const conn = ConnectionHandler.getConnection(
            userProxy,
            'Pagination_coursesOfAction',
            entityPaginationOptions,
          );
          ConnectionHandler.deleteNode(conn, courseOfAction.id);
        },
      });
    } else {
      const input = {
        fromRole: 'problem',
        toId: courseOfAction.id,
        toRole: 'mitigation',
        through: 'mitigates',
      };
      commitMutation({
        mutation: courseOfActionLinesMutationRelationAdd,
        variables: {
          id: entityId,
          input,
        },
        updater: (store) => {
          const payload = store
            .getRootField('courseOfActionEdit')
            .getLinkedRecord('relationAdd', { input });
          const container = store.getRoot();
          sharedUpdater(
            store,
            container.getDataID(),
            entityPaginationOptions,
            payload,
          );
        },
      });
    }
  }

  render() {
    const { classes, data, entityCoursesOfAction } = this.props;
    const entityCoursesOfActionIds = map(n => n.node.id, entityCoursesOfAction);
    return (
      <List>
        {data.coursesOfAction.edges.map((courseOfActionNode) => {
          const courseOfAction = courseOfActionNode.node;
          const alreadyAdded = entityCoursesOfActionIds.includes(
            courseOfAction.id,
          );
          return (
            <ListItem
              key={courseOfAction.id}
              classes={{ root: classes.menuItem }}
              divider={true}
              button={true}
              onClick={this.toggleCourseOfAction.bind(this, courseOfAction)}
            >
              <ListItemIcon>
                {alreadyAdded ? (
                  <CheckCircle classes={{ root: classes.icon }} />
                ) : (
                  <Avatar classes={{ root: classes.avatar }}>
                    {courseOfAction.name.substring(0, 1)}
                  </Avatar>
                )}
              </ListItemIcon>
              <ListItemText
                primary={courseOfAction.name}
                secondary={truncate(courseOfAction.description, 120)}
              />
            </ListItem>
          );
        })}
      </List>
    );
  }
}

AddCoursesOfActionLinesContainer.propTypes = {
  entityId: PropTypes.string,
  entityCoursesOfAction: PropTypes.array,
  entityPaginationOptions: PropTypes.object,
  data: PropTypes.object,
  classes: PropTypes.object,
};

export const addCoursesOfActionLinesQuery = graphql`
  query AddCoursesOfActionLinesQuery(
    $search: String
    $count: Int!
    $cursor: ID
  ) {
    ...AddCoursesOfActionLines_data
      @arguments(search: $search, count: $count, cursor: $cursor)
  }
`;

const AddCoursesOfActionLines = createPaginationContainer(
  AddCoursesOfActionLinesContainer,
  {
    data: graphql`
      fragment AddCoursesOfActionLines_data on Query
        @argumentDefinitions(
          search: { type: "String" }
          count: { type: "Int", defaultValue: 25 }
          cursor: { type: "ID" }
        ) {
        coursesOfAction(search: $search, first: $count, after: $cursor)
          @connection(key: "Pagination_coursesOfAction") {
          edges {
            node {
              id
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
      return props.data && props.data.coursesOfAction;
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
    query: addCoursesOfActionLinesQuery,
  },
);

export default compose(
  inject18n,
  withStyles(styles),
)(AddCoursesOfActionLines);
