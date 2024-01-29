import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import makeStyles from '@mui/styles/makeStyles';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import { useFormatter } from '../../../../components/i18n';
import { TaskDetails_task$data, TaskDetails_task$key } from './__generated__/TaskDetails_task.graphql';
import ItemDueDate from '../../../../components/ItemDueDate';

const useStyles = makeStyles(() => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
}));

const TaskDetailsFragment = graphql`
  fragment TaskDetails_task on Task {
    id
    name
    due_date
    description
    workflowEnabled
    creators {
      id
      name
    }
    createdBy {
      ... on Identity {
        id
        name
        entity_type
      }
    }
    objectMarking {
      definition
      definition_type
      id
    }
    objectLabel {
      id
      value
      color
    }
    objectAssignee {
      entity_type
      id
      name
    }
    status {
      template {
        name
        color
      }
    }
  }
`;

interface TasksDetailsProps {
  tasksData: TaskDetails_task$key;
}

const TaskDetails: FunctionComponent<TasksDetailsProps> = ({ tasksData }) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();
  const data: TaskDetails_task$data = useFragment(
    TaskDetailsFragment,
    tasksData,
  );
  return (
    <div style={{ height: '100%' }}>
      <Typography variant="h4" gutterBottom={true}>
        {t_i18n('Details')}
      </Typography>
      <Paper classes={{ root: classes.paper }} variant="outlined">
        <Grid container={true} spacing={3}>
          <Grid item={true} xs={12}>
            <Typography variant="h3" gutterBottom={true}>
              {t_i18n('Description')}
            </Typography>
            <ExpandableMarkdown source={data.description} limit={300} />
          </Grid>
          <Grid item={true} xs={12}>
            <Typography variant="h3" gutterBottom={true}>
              {t_i18n('Due Date')}
            </Typography>
            <ItemDueDate due_date={data.due_date} variant={'inElement'} />
          </Grid>
        </Grid>
      </Paper>
    </div>
  );
};
export default TaskDetails;
