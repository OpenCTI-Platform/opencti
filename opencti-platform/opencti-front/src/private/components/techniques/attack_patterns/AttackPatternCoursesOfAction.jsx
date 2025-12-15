import React from 'react';
import { filter } from 'ramda';
import Typography from '@mui/material/Typography';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { Link } from 'react-router-dom';
import IconButton from '@common/button/IconButton';
import { LinkOff } from '@mui/icons-material';
import { ProgressWrench } from 'mdi-material-ui';
import { createFragmentContainer, graphql } from 'react-relay';
import { ListItemButton } from '@mui/material';
import AddCoursesOfAction from './AddCoursesOfAction';
import { addCoursesOfActionMutationRelationDelete } from './AddCoursesOfActionLines';
import { commitMutation } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';

const AttackPatternCoursesOfActionComponent = ({ attackPattern }) => {
  const { t_i18n } = useFormatter();

  const removeCourseOfAction = (courseOfActionEdge) => {
    commitMutation({
      mutation: addCoursesOfActionMutationRelationDelete,
      variables: {
        fromId: courseOfActionEdge.node.id,
        toId: attackPattern.id,
        relationship_type: 'mitigates',
      },
      updater: (store) => {
        const node = store.get(attackPattern.id);
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
  };

  return (
    <div style={{ marginTop: 20 }}>
      <div style={{ display: 'flex', flexDirection: 'row' }}>
        <Typography variant="h3" gutterBottom={true}>
          {t_i18n('Courses of action')}
        </Typography>
        <AddCoursesOfAction
          attackPattern={attackPattern}
          attackPatternCoursesOfAction={attackPattern.coursesOfAction.edges}
        />
      </div>
      <div className="clearfix" />
      <List style={{ marginTop: -10 }}>
        <FieldOrEmpty source={attackPattern.coursesOfAction.edges}>
          {attackPattern.coursesOfAction.edges.map((courseOfActionEdge) => {
            const courseOfAction = courseOfActionEdge.node;
            return (
              <ListItem
                key={courseOfAction.id}
                dense={true}
                divider={true}
                disablePadding={true}
                secondaryAction={(
                  <IconButton
                    aria-label="Remove"
                    onClick={() => removeCourseOfAction(courseOfActionEdge)}
                  >
                    <LinkOff />
                  </IconButton>
                )}
              >
                <ListItemButton
                  component={Link}
                  to={`/dashboard/techniques/courses_of_action/${courseOfAction.id}`}
                >
                  <ListItemIcon>
                    <ListItemIcon>
                      <ProgressWrench color="primary" />
                    </ListItemIcon>
                  </ListItemIcon>
                  <ListItemText primary={courseOfAction.name} />
                </ListItemButton>
              </ListItem>
            );
          })}
        </FieldOrEmpty>
      </List>
    </div>
  );
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

export default AttackPatternCoursesOfAction;
