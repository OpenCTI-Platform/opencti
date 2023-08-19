import React from 'react';
import Typography from '@mui/material/Typography';
import makeStyles from '@mui/styles/makeStyles';
import Alert from '@mui/material/Alert';
import { useFormatter } from '../../../components/i18n';
import { QueryRenderer } from '../../../relay/environment';
import TasksList, { tasksListQuery } from './tasks/TasksList';
import Loader from '../../../components/Loader';
import useAuth from '../../../utils/hooks/useAuth';
import { TASK_MANAGER } from '../../../utils/platformModulesHelper';
import ProcessingMenu from './ProcessingMenu';

const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
    padding: '0 200px 50px 0',
  },
}));

const Tasks = () => {
  const { t } = useFormatter();
  const classes = useStyles();
  const { platformModuleHelpers } = useAuth();
  const optionsInProgress = {
    count: 50,
    orderBy: 'created_at',
    orderMode: 'desc',
    includeAuthorities: true,
    filters: [{ key: 'completed', values: ['false'] }],
  };
  const optionsFinished = {
    count: 50,
    orderBy: 'created_at',
    orderMode: 'desc',
    includeAuthorities: true,
    filters: [{ key: 'completed', values: ['true'] }],
  };
  if (!platformModuleHelpers.isTasksManagerEnable()) {
    return (
      <Alert severity="info">
        {t(platformModuleHelpers.generateDisableMessage(TASK_MANAGER))}
      </Alert>
    );
  }
  return (
    <div className={classes.container}>
      <ProcessingMenu />
      <Typography variant="h4" gutterBottom={true}>
        {t('In progress tasks')}
      </Typography>
      <QueryRenderer
        query={tasksListQuery}
        variables={optionsInProgress}
        render={({ props }) => {
          if (props) {
            return <TasksList data={props} options={optionsInProgress} />;
          }
          return <Loader variant="inElement" />;
        }}
      />
      <Typography variant="h4" gutterBottom={true} style={{ marginTop: 35 }}>
        {t('Completed tasks')}
      </Typography>
      <QueryRenderer
        query={tasksListQuery}
        variables={optionsFinished}
        render={({ props }) => {
          if (props) {
            return <TasksList data={props} options={optionsFinished} />;
          }
          return <Loader variant="inElement" />;
        }}
      />
    </div>
  );
};

export default Tasks;
