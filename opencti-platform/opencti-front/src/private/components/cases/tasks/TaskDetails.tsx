import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import makeStyles from '@mui/styles/makeStyles';
import Chip from '@mui/material/Chip';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import { useFormatter } from '../../../../components/i18n';
import {
  TaskDetails_task$data,
  TaskDetails_task$key,
} from './__generated__/TaskDetails_task.graphql';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';

const useStyles = makeStyles(() => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
  label: {
    borderRadius: 5,
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
      edges {
        node {
          definition
          definition_type
          id
        }
      }
    }
    objectLabel {
      edges {
        node {
          id
          value
          color
        }
      }
    }
    objectAssignee {
      edges {
        node {
          entity_type
          id
          name
        }
      }
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
  const { t, fldt } = useFormatter();
  const classes = useStyles();
  const data: TaskDetails_task$data = useFragment(
    TaskDetailsFragment,
    tasksData,
  );
  const currentDate = new Date();
  const isoDate = currentDate.toISOString();
  return (
    <div style={{ height: '100%' }}>
      <Typography variant="h4" gutterBottom={true}>
        {t('Details')}
      </Typography>
      <Paper classes={{ root: classes.paper }} variant="outlined">
        <Grid container={true} spacing={3}>
          <Grid item={true} xs={12}>
            <Typography variant="h3" gutterBottom={true}>
              {t('Description')}
            </Typography>
            <ExpandableMarkdown source={data.description} limit={300} />
          </Grid>
          <Grid item={true} xs={12}>
            <Typography variant="h3" gutterBottom={true}>
              {t('Due Date')}
            </Typography>
            <FieldOrEmpty source={data.due_date}>
              <Chip
                label={fldt(data.due_date)}
                variant="outlined"
                color={data.due_date < isoDate ? 'error' : 'info'}
                classes={{ root: classes.label }}
              />
            </FieldOrEmpty>
          </Grid>
        </Grid>
      </Paper>
    </div>
  );
};
export default TaskDetails;
