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
import IconButton from '@mui/material/IconButton';
import { LinkOff } from '@mui/icons-material';
import { ProgressWrench } from 'mdi-material-ui';
import { createFragmentContainer, graphql } from 'react-relay';
import AddCoursesOfAction from './AddCoursesOfAction';
import { addCoursesOfActionMutationRelationDelete } from './AddCoursesOfActionLines';
import { commitMutation } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';

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
      <div style={{ marginTop: 20 }}>
        <div style={{ display: 'flex', flexDirection: 'row' }}>
          <Typography variant="h3" gutterBottom={true}>
            {t('Courses of action')}
          </Typography>
          <AddCoursesOfAction
            attackPattern={attackPattern}
            attackPatternCoursesOfAction={attackPattern.coursesOfAction.edges}
          />
        </div>
        <div className="clearfix" />
        <List style={{ marginTop: -10, paddingTop: 0 }}>
          <FieldOrEmpty source={attackPattern.coursesOfAction.edges}>
            {attackPattern.coursesOfAction.edges.map((courseOfActionEdge) => {
              const courseOfAction = courseOfActionEdge.node;
              return (
                <ListItem
                  key={courseOfAction.id}
                  dense={true}
                  divider={true}
                  component={Link}
                  to={`/dashboard/techniques/courses_of_action/${courseOfAction.id}`}
                  secondaryAction={
                    <IconButton
                      aria-label="Remove"
                      onClick={this.removeCourseOfAction.bind(
                        this,
                        courseOfActionEdge,
                      )}
                      size="large"
                    >
                      <LinkOff/>
                    </IconButton>
                  }
                >
                  <ListItemIcon>
                    <ListItemIcon>
                      <ProgressWrench color="primary"/>
                    </ListItemIcon>
                  </ListItemIcon>
                  <ListItemText primary={courseOfAction.name}/>
                </ListItem>
              );
            })}
          </FieldOrEmpty>
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
        name
        parent_types
        entity_type
        coursesOfAction {
          edges {
            node {
              id
              parent_types
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
