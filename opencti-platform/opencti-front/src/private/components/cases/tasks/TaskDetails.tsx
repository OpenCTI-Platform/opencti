import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import makeStyles from '@mui/styles/makeStyles';
import Chip from '@mui/material/Chip';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import { useFormatter } from '../../../../components/i18n';
import { TaskDetails_task$data, TaskDetails_task$key } from './__generated__/TaskDetails_task.graphql';
import { Theme } from '../../../../components/Theme';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';

const styles = makeStyles<Theme>((theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
  labelInDetails: {
    border: 'none',
    fontSize: 12,
    lineHeight: '12px',
    backgroundColor: theme.palette.background.accent,
    borderRadius: 5,
    color: theme.palette.text?.primary,
    textTransform: 'uppercase',
    margin: '0 5px 5px 0',
  },
  labelErrorInDetails: {
    border: 'none',
    fontSize: 12,
    lineHeight: '12px',
    backgroundColor: theme.palette.error.dark,
    borderRadius: 5,
    color: theme.palette.text?.primary,
    textTransform: 'uppercase',
    margin: '0 5px 5px 0',
  },
}));

const TaskDetailsFragment = graphql`
  fragment TaskDetails_task on Task {
    id
    name
    dueDate
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

const TaskDetails: FunctionComponent<TasksDetailsProps> = ({
  tasksData,
}) => {
  const { t, fldt } = useFormatter();
  const classes = styles();
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
            <FieldOrEmpty source={data.description}>
              {data.description && (
                <ExpandableMarkdown source={data.description} limit={300} />
              )}
            </FieldOrEmpty>
          </Grid>
          <Grid item={true} xs={12}>
            <Typography variant="h3" gutterBottom={true}>
              {t('Due Date')}
            </Typography>
            <FieldOrEmpty source={data.dueDate}>
              {data.dueDate && (
                <Chip
                  label={fldt(data.dueDate)}
                  classes={{ root: data.dueDate < isoDate ? classes.labelErrorInDetails : classes.labelInDetails }}
                />
              )}
            </FieldOrEmpty>
          </Grid>
        </Grid>
      </Paper>
    </div>
  );
};
export default TaskDetails;
