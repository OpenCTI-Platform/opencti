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

const addAattackPatternsLinesMutationRelationAdd = graphql`
  mutation AddAttackPatternsLinesRelationAddMutation(
    $input: StixCoreRelationshipAddInput
  ) {
    stixCoreRelationshipAdd(input: $input) {
      from {
        ...CourseOfActionAttackPatterns_courseOfAction
      }
    }
  }
`;

export const addAttackPatternsLinesMutationRelationDelete = graphql`
  mutation AddAttackPatternsLinesRelationDeleteMutation(
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

class AddAttackPatternsLinesContainer extends Component {
  toggleAttackPattern(attackPattern) {
    const { courseOfActionId, courseOfActionAttackPatterns } = this.props;
    const entityCoursesOfActionIds = map(
      (n) => n.node.id,
      courseOfActionAttackPatterns,
    );
    const alreadyAdded = entityCoursesOfActionIds.includes(attackPattern.id);

    if (alreadyAdded) {
      const existingAttackPattern = head(
        filter(
          (n) => n.node.id === attackPattern.id,
          courseOfActionAttackPatterns,
        ),
      );
      commitMutation({
        mutation: addAttackPatternsLinesMutationRelationDelete,
        variables: {
          fromId: courseOfActionId,
          toId: existingAttackPattern.node.id,
          relationship_type: 'mitigates',
        },
        updater: (store) => {
          const node = store.get(this.props.courseOfActionId);
          const attackPatterns = node.getLinkedRecord('attackPatterns');
          const edges = attackPatterns.getLinkedRecords('edges');
          const newEdges = filter(
            (n) => n.getLinkedRecord('node').getValue('id')
              !== existingAttackPattern.node.id,
            edges,
          );
          attackPatterns.setLinkedRecords(newEdges, 'edges');
        },
      });
    } else {
      const input = {
        relationship_type: 'mitigates',
        fromId: courseOfActionId,
        toId: attackPattern.id,
      };
      commitMutation({
        mutation: addAattackPatternsLinesMutationRelationAdd,
        variables: { input },
      });
    }
  }

  render() {
    const { classes, data, courseOfActionAttackPatterns } = this.props;
    const courseOfActionAttackPatternsIds = map(
      (n) => n.node.id,
      courseOfActionAttackPatterns,
    );
    return (
      <List>
        {data.attackPatterns.edges.map((attackPatternNode) => {
          const attackPattern = attackPatternNode.node;
          const alreadyAdded = courseOfActionAttackPatternsIds.includes(
            attackPattern.id,
          );
          return (
            <ListItem
              key={attackPattern.id}
              classes={{ root: classes.menuItem }}
              divider={true}
              button={true}
              onClick={this.toggleAttackPattern.bind(this, attackPattern)}
            >
              <ListItemIcon>
                {alreadyAdded ? (
                  <CheckCircle classes={{ root: classes.icon }} />
                ) : (
                  <Avatar classes={{ root: classes.avatar }}>
                    {attackPattern.name.substring(0, 1)}
                  </Avatar>
                )}
              </ListItemIcon>
              <ListItemText
                primary={attackPattern.name}
                secondary={truncate(attackPattern.description, 120)}
              />
            </ListItem>
          );
        })}
      </List>
    );
  }
}

AddAttackPatternsLinesContainer.propTypes = {
  courseOfActionId: PropTypes.string,
  courseOfActionAttackPatterns: PropTypes.array,
  data: PropTypes.object,
  classes: PropTypes.object,
};

export const addAttackPatternsLinesQuery = graphql`
  query AddAttackPatternsLinesQuery(
    $search: String
    $count: Int!
    $cursor: ID
  ) {
    ...AddAttackPatternsLines_data
      @arguments(search: $search, count: $count, cursor: $cursor)
  }
`;

const AddAttackPatternsLines = createPaginationContainer(
  AddAttackPatternsLinesContainer,
  {
    data: graphql`
      fragment AddAttackPatternsLines_data on Query
      @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
      ) {
        attackPatterns(search: $search, first: $count, after: $cursor)
          @connection(key: "Pagination_attackPatterns") {
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
      return props.data && props.data.attackPatterns;
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
    query: addAttackPatternsLinesQuery,
  },
);

export default compose(inject18n, withStyles(styles))(AddAttackPatternsLines);
