import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer } from 'react-relay';
import { ConnectionHandler } from 'relay-runtime';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction';
import IconButton from '@material-ui/core/IconButton';
import Avatar from '@material-ui/core/Avatar';
import { LinkOff } from '@material-ui/icons';
import { compose } from 'ramda';
import { Link } from 'react-router-dom';
import Typography from '@material-ui/core/Typography';
import inject18n from '../../../../components/i18n';
import { truncate } from '../../../../utils/String';
import { commitMutation } from '../../../../relay/environment';
import { attackPatternsLinesMutationRelationDelete } from './AddAttackPatternsLines';
import AddAttackPatterns from './AddAttackPatterns';

const styles = (theme) => ({
  paper: {
    minHeight: '100%',
    margin: '-4px 0 0 0',
    padding: 0,
    borderRadius: 6,
  },
  list: {
    padding: 0,
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

class CourseOfActionAttackPatternsLinesContainer extends Component {
  removeAttackPattern(attackPatternEdge) {
    commitMutation({
      mutation: attackPatternsLinesMutationRelationDelete,
      variables: {
        id: attackPatternEdge.node.id,
        relationId: attackPatternEdge.relation.id,
      },
      updater: (store) => {
        const container = store.getRoot();
        const userProxy = store.get(container.getDataID());
        const conn = ConnectionHandler.getConnection(
          userProxy,
          'Pagination_attackPatterns',
          this.props.paginationOptions,
        );
        ConnectionHandler.deleteNode(conn, attackPatternEdge.node.id);
      },
    });
  }

  render() {
    const {
      t,
      classes,
      courseOfActionId,
      paginationOptions,
      data,
    } = this.props;
    return (
      <div style={{ marginTop: 20 }}>
        <Typography variant="h3" gutterBottom={true} style={{ float: 'left' }}>
          {t('Mitigated TTPs')}
        </Typography>
        <AddAttackPatterns
          courseOfActionId={courseOfActionId}
          courseOfActionAttackPatterns={data.attackPatterns.edges}
          courseOfActionPaginationOptions={paginationOptions}
        />
        <div className="clearfix" />
        <List classes={{ root: classes.list }}>
          {data.attackPatterns.edges.map((attackPatternEdge) => {
            const attackPattern = attackPatternEdge.node;
            return (
              <ListItem
                key={attackPattern.id}
                dense={true}
                divider={true}
                button={true}
                component={Link}
                to={`/dashboard/techniques/attack_patterns/${attackPattern.id}`}
              >
                <ListItemIcon>
                  <Avatar classes={{ root: classes.avatar }}>
                    {attackPattern.name.substring(0, 1)}
                  </Avatar>
                </ListItemIcon>
                <ListItemText
                  primary={attackPattern.name}
                  secondary={truncate(attackPattern.description, 60)}
                />
                <ListItemSecondaryAction>
                  <IconButton
                    aria-label="Remove"
                    onClick={this.removeAttackPattern.bind(
                      this,
                      attackPatternEdge,
                    )}
                  >
                    <LinkOff />
                  </IconButton>
                </ListItemSecondaryAction>
              </ListItem>
            );
          })}
        </List>
      </div>
    );
  }
}

CourseOfActionAttackPatternsLinesContainer.propTypes = {
  courseOfActionId: PropTypes.string,
  paginationOptions: PropTypes.object,
  data: PropTypes.object,
  limit: PropTypes.number,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

export const courseOfActionAttackPatternsLinesQuery = graphql`
  query CourseOfActionAttackPatternsLinesQuery(
    $courseOfActionId: String!
    $count: Int!
    $cursor: ID
    $orderBy: AttackPatternsOrdering
    $orderMode: OrderingMode
  ) {
    ...CourseOfActionAttackPatternsLines_data
      @arguments(
        courseOfActionId: $courseOfActionId
        count: $count
        cursor: $cursor
        orderBy: $orderBy
        orderMode: $orderMode
      )
  }
`;

const CourseOfActionAttackPatternsLines = createPaginationContainer(
  CourseOfActionAttackPatternsLinesContainer,
  {
    data: graphql`
      fragment CourseOfActionAttackPatternsLines_data on Query
        @argumentDefinitions(
          courseOfActionId: { type: "String!" }
          count: { type: "Int", defaultValue: 25 }
          cursor: { type: "ID" }
          orderBy: { type: "AttackPatternsOrdering", defaultValue: "name" }
          orderMode: { type: "OrderingMode", defaultValue: "asc" }
        ) {
        attackPatterns(
          courseOfActionId: $courseOfActionId
          first: $count
          after: $cursor
          orderBy: $orderBy
          orderMode: $orderMode
        ) @connection(key: "Pagination_attackPatterns") {
          edges {
            node {
              id
              name
              description
            }
            relation {
              id
            }
          }
          pageInfo {
            endCursor
            hasNextPage
            globalCount
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
        courseOfActionId: fragmentVariables.courseOfActionId,
        count,
        cursor,
        orderBy: fragmentVariables.orderBy,
        orderMode: fragmentVariables.orderMode,
      };
    },
    query: courseOfActionAttackPatternsLinesQuery,
  },
);

export default compose(
  inject18n,
  withStyles(styles),
)(CourseOfActionAttackPatternsLines);
