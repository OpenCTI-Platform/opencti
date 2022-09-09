import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createPaginationContainer } from 'react-relay';
import { map, filter, head, compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { CheckCircle } from '@mui/icons-material';
import { ProgressWrench } from 'mdi-material-ui';
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

const addCoursesOfActionLinesMutationRelationAdd = graphql`
  mutation AddCoursesOfActionLinesRelationAddMutation(
    $input: StixCoreRelationshipAddInput
  ) {
    stixCoreRelationshipAdd(input: $input) {
      to {
        ...AttackPatternCoursesOfAction_attackPattern
      }
    }
  }
`;

export const addCoursesOfActionMutationRelationDelete = graphql`
  mutation AddCoursesOfActionLinesRelationDeleteMutation(
    $fromId: StixRef!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    stixCoreRelationshipDelete(
      fromId: $fromId
      toId: $toId
      relationship_type: $relationship_type
    )
  }
`;

class AddCoursesOfActionLinesContainer extends Component {
  toggleCourseOfAction(courseOfAction) {
    const { attackPatternId, attackPatternCoursesOfAction } = this.props;
    const attackPatternCoursesOfActionIds = map(
      (n) => n.node.id,
      attackPatternCoursesOfAction,
    );
    const alreadyAdded = attackPatternCoursesOfActionIds.includes(
      courseOfAction.id,
    );
    if (alreadyAdded) {
      const existingCourseOfAction = head(
        filter(
          (n) => n.node.id === courseOfAction.id,
          attackPatternCoursesOfAction,
        ),
      );
      commitMutation({
        mutation: addCoursesOfActionMutationRelationDelete,
        variables: {
          fromId: existingCourseOfAction.node.id,
          toId: attackPatternId,
          relationship_type: 'mitigates',
        },
        updater: (store) => {
          const node = store.get(attackPatternId);
          const coursesOfAction = node.getLinkedRecord('coursesOfAction');
          const edges = coursesOfAction.getLinkedRecords('edges');
          const newEdges = filter(
            (n) => n.getLinkedRecord('node').getValue('id')
              !== existingCourseOfAction.node.id,
            edges,
          );
          coursesOfAction.setLinkedRecords(newEdges, 'edges');
        },
      });
    } else {
      const input = {
        relationship_type: 'mitigates',
        fromId: courseOfAction.id,
        toId: attackPatternId,
      };
      commitMutation({
        mutation: addCoursesOfActionLinesMutationRelationAdd,
        variables: { input },
      });
    }
  }

  render() {
    const { classes, data, attackPatternCoursesOfAction } = this.props;
    const attackPatternCoursesOfActionIds = map(
      (n) => n.node.id,
      attackPatternCoursesOfAction,
    );
    return (
      <List>
        {data.coursesOfAction.edges.map((courseOfActionNode) => {
          const courseOfAction = courseOfActionNode.node;
          const alreadyAdded = attackPatternCoursesOfActionIds.includes(
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
                  <ProgressWrench />
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
  attackPatternId: PropTypes.string,
  attackPatternCoursesOfAction: PropTypes.array,
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

export default compose(inject18n, withStyles(styles))(AddCoursesOfActionLines);
