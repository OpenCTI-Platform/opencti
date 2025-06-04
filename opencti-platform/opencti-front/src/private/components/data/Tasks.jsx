import React from 'react';
import makeStyles from '@mui/styles/makeStyles';
import Alert from '@mui/material/Alert';
import { useFormatter } from '../../../components/i18n';
import { QueryRenderer } from '../../../relay/environment';
import TasksList, { tasksListQuery } from './tasks/TasksList';
import Loader from '../../../components/Loader';
import useAuth from '../../../utils/hooks/useAuth';
import { TASK_MANAGER } from '../../../utils/platformModulesHelper';
import ProcessingMenu from './ProcessingMenu';
import Breadcrumbs from '../../../components/Breadcrumbs';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
    padding: '0 200px 50px 0',
  },
}));

const Tasks = () => {
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Tasks | Processing | Data'));
  const classes = useStyles();
  const { platformModuleHelpers } = useAuth();
  const optionsInTasks = {
    count: 100,
    orderBy: 'created_at',
    orderMode: 'desc',
    includeAuthorities: true,
  };
  if (!platformModuleHelpers.isTasksManagerEnable()) {
    return (
      <div className={classes.container}>
        <Alert severity="info">
          {t_i18n(platformModuleHelpers.generateDisableMessage(TASK_MANAGER))}
        </Alert>
        <ProcessingMenu />
      </div>
    );
  }
  return (
    <div className={classes.container}
      data-testid='processing-tasks-page'
    >
      <Breadcrumbs elements={[{ label: t_i18n('Data') }, { label: t_i18n('Processing') }, { label: t_i18n('Tasks'), current: true }]} />
      <ProcessingMenu />
      <QueryRenderer
        query={tasksListQuery}
        variables={optionsInTasks}
        render={({ props }) => {
          if (props) {
            return <TasksList data={props} options={optionsInTasks} />;
          }
          return <Loader variant="inElement" />;
        }}
      />
    </div>
  );
};

export default Tasks;
