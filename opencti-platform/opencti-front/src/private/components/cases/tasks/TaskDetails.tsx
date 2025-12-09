import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import { useFormatter } from '../../../../components/i18n';
import { TaskDetails_task$data, TaskDetails_task$key } from './__generated__/TaskDetails_task.graphql';
import ItemDueDate from '../../../../components/ItemDueDate';
import Card from '../../../../components/common/card/Card';

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
  const data: TaskDetails_task$data = useFragment(
    TaskDetailsFragment,
    tasksData,
  );
  return (
    <div style={{ height: '100%' }} data-testid="task-details-page">
      <Card title={t_i18n('Details')}>
        <Grid container={true} spacing={3}>
          <Grid item xs={12}>
            <Typography variant="h3" gutterBottom={true}>
              {t_i18n('Description')}
            </Typography>
            <ExpandableMarkdown source={data.description} limit={300} />
          </Grid>
          <Grid item xs={12}>
            <Typography variant="h3" gutterBottom={true}>
              {t_i18n('Due Date')}
            </Typography>
            <ItemDueDate due_date={data.due_date} variant="inElement" />
          </Grid>
        </Grid>
      </Card>
    </div>
  );
};
export default TaskDetails;
