import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, filter } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Typography from '@mui/material/Typography';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Avatar from '@mui/material/Avatar';
import { Link } from 'react-router-dom';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import IconButton from '@mui/material/IconButton';
import { LinkOff } from '@mui/icons-material';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { truncate } from '../../../../utils/String';
import AddCoursesOfAction from './AddAttackPatterns';
import { addAttackPatternsLinesMutationRelationDelete } from './AddAttackPatternsLines';
import { commitMutation } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';

const styles = (theme) => ({
  avatar: {
    width: 24,
    height: 24,
    backgroundColor: theme.palette.primary.main,
  },
  list: {
    padding: 0,
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

class CourseOfActionAttackPatternComponent extends Component {
  removeAttackPattern(attackPatternEdge) {
    commitMutation({
      mutation: addAttackPatternsLinesMutationRelationDelete,
      variables: {
        id: attackPatternEdge.relation.id,
      },
      updater: (store) => {
        const node = store.get(this.props.courseOfAction.id);
        const attackPatterns = node.getLinkedRecord('attackPatterns');
        const edges = attackPatterns.getLinkedRecords('edges');
        const newEdges = filter(
          (n) => n.getLinkedRecord('node').getValue('id')
            !== attackPatternEdge.node.id,
          edges,
        );
        attackPatterns.setLinkedRecords(newEdges, 'edges');
      },
    });
  }

  render() {
    const { t, classes, courseOfAction } = this.props;
    return (
      <div style={{ marginTop: 20 }}>
        <Typography variant="h3" gutterBottom={true} style={{ float: 'left' }}>
          {t('Mitigated attack patterns')}
        </Typography>
        <AddCoursesOfAction
          courseOfActionId={courseOfAction.id}
          courseOfActionAttackPatterns={courseOfAction.attackPatterns.edges}
        />
        <div className="clearfix" />
        <List classes={{ root: classes.list }}>
          {courseOfAction.attackPatterns.edges.map((attackPatternEdge) => {
            const attackPattern = attackPatternEdge.node;
            return (
              <ListItem
                key={attackPattern.id}
                dense={true}
                divider={true}
                button={true}
                component={Link}
                to={`/dashboard/arsenal/attack_patterns/${attackPattern.id}`}
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
                    size="large"
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

CourseOfActionAttackPatternComponent.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
  courseOfAction: PropTypes.object,
};

const CourseOfActionAttackPattern = createFragmentContainer(
  CourseOfActionAttackPatternComponent,
  {
    courseOfAction: graphql`
      fragment CourseOfActionAttackPatterns_courseOfAction on CourseOfAction {
        id
        attackPatterns {
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
);

export default compose(
  inject18n,
  withStyles(styles),
)(CourseOfActionAttackPattern);
