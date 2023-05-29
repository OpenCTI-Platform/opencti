import { Close } from '@mui/icons-material';
import IconButton from '@mui/material/IconButton';
import Typography from '@mui/material/Typography';
import makeStyles from '@mui/styles/makeStyles';
import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import { useFormatter } from '../../../../components/i18n';
import { SubscriptionAvatars } from '../../../../components/Subscription';
import { Theme } from '../../../../components/Theme';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import TasksEditionOverview from './TasksEditionOverview';
import { TasksEditionContainerQuery } from './__generated__/TasksEditionContainerQuery.graphql';

const useStyles = makeStyles<Theme>((theme) => ({
  header: {
    backgroundColor: theme.palette.background.nav,
    padding: '20px 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
    color: 'inherit',
  },
  container: {
    padding: '10px 20px 20px 20px',
  },
  title: {
    float: 'left',
  },
}));

interface TasksEditionContainerProps {
  queryRef: PreloadedQuery<TasksEditionContainerQuery>
  handleClose: () => void
}

export const tasksEditionQuery = graphql`
  query TasksEditionContainerQuery($id: String!) {
    caseTask(id: $id) {
      ...TasksEditionOverview_task
      editContext {
        name
        focusOn
      }
    }
  }
`;

const TasksEditionContainer: FunctionComponent<
TasksEditionContainerProps
> = ({ queryRef, handleClose }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const queryData = usePreloadedQuery(tasksEditionQuery, queryRef);
  if (queryData.caseTask === null) {
    return <ErrorNotFound />;
  }
  return (
    <div>
      <div className={classes.header}>
        <IconButton
          aria-label="Close"
          className={classes.closeButton}
          onClick={handleClose}
          size="large"
          color="primary"
        >
          <Close fontSize="small" color="primary" />
        </IconButton>
        <Typography variant="h6" classes={{ root: classes.title }}>
          {t('Update a task')}
        </Typography>
        <SubscriptionAvatars context={queryData.caseTask.editContext} />
        <div className="clearfix" />
      </div>
      <div className={classes.container}>
        <TasksEditionOverview
          taskRef={queryData.caseTask}
          context={queryData.caseTask.editContext}
          enableReferences={useIsEnforceReference('Case-Task')}
          handleClose={handleClose}
        />
      </div>
    </div>
  );
};

export default TasksEditionContainer;
