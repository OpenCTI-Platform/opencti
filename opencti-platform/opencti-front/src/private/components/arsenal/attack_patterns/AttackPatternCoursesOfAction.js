import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, filter } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Typography from '@mui/material/Typography';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { Link } from 'react-router-dom';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import IconButton from '@mui/material/IconButton';
import { LinkOff } from '@mui/icons-material';
import { ProgressWrench } from 'mdi-material-ui';
import { graphql, createFragmentContainer } from 'react-relay';
import AddCoursesOfAction from './AddCoursesOfAction';
import { addCoursesOfActionMutationRelationDelete } from './AddCoursesOfActionLines';
import { commitMutation } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';

const styles = (theme) => ({
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

class AttackPatternCoursesOfActionComponent extends Component {
  removeCourseOfAction(courseOfActionEdge) {
    commitMutation({
      mutation: addCoursesOfActionMutationRelationDelete,
      variables: {
        fromId: courseOfActionEdge.node.id,
        toId: this.props.attackPattern.id,
        relationship_type: 'mitigates',
      },
      updater: (store) => {
        const node = store.get(this.props.attackPattern.id);
        const coursesOfAction = node.getLinkedRecord('coursesOfAction');
        const edges = coursesOfAction.getLinkedRecords('edges');
        const newEdges = filter(
          (n) => n.getLinkedRecord('node').getValue('id')
            !== courseOfActionEdge.node.id,
          edges,
        );
        coursesOfAction.setLinkedRecords(newEdges, 'edges');
      },
    });
  }

  render() {
    const { t, attackPattern } = this.props;
    return (
      <div style={{ height: '100%', marginTop: 20 }}>
        <Typography variant="h3" gutterBottom={true} style={{ float: 'left' }}>
          {t('Courses of action')}
        </Typography>
        <AddCoursesOfAction
          attackPatternId={attackPattern.id}
          attackPatternCoursesOfAction={attackPattern.coursesOfAction.edges}
        />
        <div className="clearfix" />
        <List style={{ marginTop: -10 }}>
          {attackPattern.coursesOfAction.edges.map((courseOfActionEdge) => {
            const courseOfAction = courseOfActionEdge.node;
            return (
              <ListItem
                key={courseOfAction.id}
                dense={true}
                divider={true}
                button={true}
                component={Link}
                to={`/dashboard/arsenal/courses_of_action/${courseOfAction.id}`}
              >
                <ListItemIcon>
                  <ListItemIcon>
                    <ProgressWrench color="primary" />
                  </ListItemIcon>
                </ListItemIcon>
                <ListItemText primary={courseOfAction.name} />
                <ListItemSecondaryAction>
                  <IconButton
                    aria-label="Remove"
                    onClick={this.removeCourseOfAction.bind(
                      this,
                      courseOfActionEdge,
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

AttackPatternCoursesOfActionComponent.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
  attackPattern: PropTypes.object,
};

const AttackPatternCoursesOfAction = createFragmentContainer(
  AttackPatternCoursesOfActionComponent,
  {
    attackPattern: graphql`
      fragment AttackPatternCoursesOfAction_attackPattern on AttackPattern {
        id
        coursesOfAction {
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
)(AttackPatternCoursesOfAction);
