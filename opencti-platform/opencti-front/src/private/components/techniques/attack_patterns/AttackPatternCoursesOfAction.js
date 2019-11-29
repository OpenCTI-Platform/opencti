import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import Avatar from '@material-ui/core/Avatar';
import { Link } from 'react-router-dom';
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction';
import IconButton from '@material-ui/core/IconButton';
import { LinkOff } from '@material-ui/icons';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { truncate } from '../../../../utils/String';
import AddCoursesOfAction from './AddCoursesOfAction';
import { addCoursesOfActionMutationRelationDelete } from './AddCoursesOfActionLines';
import { commitMutation } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';

const styles = (theme) => ({
  paper: {
    minHeight: '100%',
    margin: '-4px 0 0 0',
    padding: 0,
    borderRadius: 6,
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

class AttackPatternCoursesOfActionComponent extends Component {
  removeCourseOfAction(courseOfActionEdge) {
    commitMutation({
      mutation: addCoursesOfActionMutationRelationDelete,
      variables: {
        id: this.props.attackPattern.id,
        relationId: courseOfActionEdge.relation.id,
      },
    });
  }

  render() {
    const { t, classes, attackPattern } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
          {t('Courses of action')}
        </Typography>
        <AddCoursesOfAction
          attackPatternId={attackPattern.id}
          attackPatternCoursesOfAction={attackPattern.coursesOfAction.edges}
        />
        <div className="clearfix" />
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <List>
            {attackPattern.coursesOfAction.edges.map((courseOfActionEdge) => {
              const courseOfAction = courseOfActionEdge.node;
              return (
                <ListItem
                  key={courseOfAction.id}
                  dense={true}
                  divider={true}
                  button={true}
                  component={Link}
                  to={`/dashboard/techniques/courses_of_action/${courseOfAction.id}`}
                >
                  <ListItemIcon>
                    <Avatar classes={{ root: classes.avatar }}>
                      {courseOfAction.name.substring(0, 1)}
                    </Avatar>
                  </ListItemIcon>
                  <ListItemText
                    primary={courseOfAction.name}
                    secondary={truncate(courseOfAction.description, 60)}
                  />
                  <ListItemSecondaryAction>
                    <IconButton
                      aria-label="Remove"
                      onClick={this.removeCourseOfAction.bind(
                        this,
                        courseOfActionEdge,
                      )}
                    >
                      <LinkOff />
                    </IconButton>
                  </ListItemSecondaryAction>
                </ListItem>
              );
            })}
          </List>
        </Paper>
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
            relation {
              id
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
