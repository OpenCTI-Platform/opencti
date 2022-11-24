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
import { LockPattern } from 'mdi-material-ui';
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

const addSubAttackPatternsLinesMutationRelationAdd = graphql`
  mutation AddSubAttackPatternsLinesRelationAddMutation(
    $input: StixCoreRelationshipAddInput
  ) {
    stixCoreRelationshipAdd(input: $input) {
      to {
        ...AttackPatternSubAttackPatterns_attackPattern
      }
    }
  }
`;

export const addSubAttackPatternsMutationRelationDelete = graphql`
  mutation AddSubAttackPatternsLinesRelationDeleteMutation(
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

class AddSubAttackPatternsLinesContainer extends Component {
  toggleSubAttackPattern(subAttackPattern) {
    const { attackPatternId, attackPatternSubAttackPatterns } = this.props;
    const attackPatternSubAttackPatternsIds = map(
      (n) => n.node.id,
      attackPatternSubAttackPatterns,
    );
    const alreadyAdded = attackPatternSubAttackPatternsIds.includes(
      subAttackPattern.id,
    );

    if (alreadyAdded) {
      const existingSubAttackPattern = head(
        filter(
          (n) => n.node.id === subAttackPattern.id,
          attackPatternSubAttackPatterns,
        ),
      );
      commitMutation({
        mutation: addSubAttackPatternsMutationRelationDelete,
        variables: {
          fromId: existingSubAttackPattern.node.id,
          toId: attackPatternId,
          relationship_type: 'subtechnique-of',
        },
        updater: (store) => {
          const node = store.get(this.props.attackPatternId);
          const subAttackPatterns = node.getLinkedRecord('subAttackPatterns');
          const edges = subAttackPatterns.getLinkedRecords('edges');
          const newEdges = filter(
            (n) => n.getLinkedRecord('node').getValue('id')
              !== existingSubAttackPattern.node.id,
            edges,
          );
          subAttackPatterns.setLinkedRecords(newEdges, 'edges');
        },
      });
    } else {
      const input = {
        relationship_type: 'subtechnique-of',
        fromId: subAttackPattern.id,
        toId: attackPatternId,
      };
      commitMutation({
        mutation: addSubAttackPatternsLinesMutationRelationAdd,
        variables: { input },
      });
    }
  }

  render() {
    const { classes, data, attackPatternSubAttackPatterns } = this.props;
    const attackPatternSubAttackPatternsIds = map(
      (n) => n.node.id,
      attackPatternSubAttackPatterns,
    );
    return (
      <List>
        {data.attackPatterns.edges.map((attackPatternNode) => {
          const attackPattern = attackPatternNode.node;
          const alreadyAdded = attackPatternSubAttackPatternsIds.includes(
            attackPattern.id,
          );
          return (
            <ListItem
              key={attackPattern.id}
              classes={{ root: classes.menuItem }}
              divider={true}
              button={true}
              onClick={this.toggleSubAttackPattern.bind(this, attackPattern)}
            >
              <ListItemIcon>
                {alreadyAdded ? (
                  <CheckCircle classes={{ root: classes.icon }} />
                ) : (
                  <LockPattern />
                )}
              </ListItemIcon>
              <ListItemText
                primary={`${
                  attackPattern.x_mitre_id
                    ? `${attackPattern.x_mitre_id} - `
                    : ''
                }${attackPattern.name}`}
                secondary={truncate(attackPattern.description, 120)}
              />
            </ListItem>
          );
        })}
      </List>
    );
  }
}

AddSubAttackPatternsLinesContainer.propTypes = {
  attackPatternId: PropTypes.string,
  attackPatternSubAttackPatterns: PropTypes.array,
  data: PropTypes.object,
  classes: PropTypes.object,
};

export const addSubAttackPatternsLinesQuery = graphql`
  query AddSubAttackPatternsLinesQuery(
    $search: String
    $count: Int!
    $cursor: ID
  ) {
    ...AddSubAttackPatternsLines_data
      @arguments(search: $search, count: $count, cursor: $cursor)
  }
`;

const AddSubAttackPatternsLines = createPaginationContainer(
  AddSubAttackPatternsLinesContainer,
  {
    data: graphql`
      fragment AddSubAttackPatternsLines_data on Query
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
              x_mitre_id
            }
          }
        }
      }
    `,
  },
  {
    direction: 'forward',
    getConnectionFromProps(props) {
      return props.data && props.data.subAttackPatterns;
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
    query: addSubAttackPatternsLinesQuery,
  },
);

export default compose(
  inject18n,
  withStyles(styles),
)(AddSubAttackPatternsLines);
