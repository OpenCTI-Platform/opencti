import React, { useState } from 'react';
import * as R from 'ramda';
import { graphql, useFragment } from 'react-relay';
import Grid from '@mui/material/Grid';
import Typography from '@mui/material/Typography';
import Tooltip from '@mui/material/Tooltip';
import LinearProgress from '@mui/material/LinearProgress';
import Paper from '@mui/material/Paper';
import Button from '@common/button/Button';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import Table from '@mui/material/Table';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableContainer from '@mui/material/TableContainer';
import TableHead from '@mui/material/TableHead';
import TableRow from '@mui/material/TableRow';
import Slide from '@mui/material/Slide';
import { Delete } from 'mdi-material-ui';
import Chip from '@mui/material/Chip';
import makeStyles from '@mui/styles/makeStyles';
import TasksFilterValueContainer from '../../../../components/TasksFilterValueContainer';
import TaskStatus from '../../../../components/TaskStatus';
import { useFormatter } from '../../../../components/i18n';
import { truncate } from '../../../../utils/String';
import { commitMutation, MESSAGING$ } from '../../../../relay/environment';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import TaskScope from '../../../../components/TaskScope';
import { deserializeFilterGroupForFrontend, isFilterFormatCorrect, isFilterGroupNotEmpty } from '../../../../utils/filters/filtersUtils';
import { convertFiltersFromOldFormat } from '../../../../utils/filters/filtersFromOldFormat';
import { deleteNode } from '../../../../utils/store';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles((theme) => ({
  paper: {
    marginTop: theme.spacing(1),
    padding: '15px',
    borderRadius: 4,
    position: 'relative',
  },
  progress: {
    borderRadius: 4,
    height: 10,
  },
  filter: {
    margin: '5px 10px 5px 0',
  },
  operator: {
    fontFamily: 'Consolas, monaco, monospace',
    backgroundColor: theme.palette.background.accent,
    margin: '5px 10px 5px 0',
  },
}));

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

export const tasksListTaskDeletionMutation = graphql`
  mutation TasksListTaskDeletionMutation($id: ID!) {
    deleteBackgroundTask(id: $id)
  }
`;

export const tasksListQuery = graphql`
  query TasksListQuery(
    $count: Int
    $orderBy: BackgroundTasksOrdering
    $orderMode: OrderingMode
    $includeAuthorities: Boolean
    $filters: FilterGroup
  ) {
    ...TasksList_data
    @arguments(
      count: $count
      orderBy: $orderBy
      orderMode: $orderMode
      includeAuthorities: $includeAuthorities
      filters: $filters
    )
  }
`;

const TasksListFragment = graphql`
  fragment TasksList_data on Query
  @argumentDefinitions(
    count: { type: "Int" }
    orderBy: { type: "BackgroundTasksOrdering", defaultValue: created_at }
    orderMode: { type: "OrderingMode", defaultValue: desc }
    includeAuthorities: { type: "Boolean", defaultValue: true }
    filters: { type: "FilterGroup" }
  ) {
    backgroundTasks(
      first: $count
      orderBy: $orderBy
      orderMode: $orderMode
      includeAuthorities: $includeAuthorities
      filters: $filters
    ) @connection(key: "Pagination_backgroundTasks") {
      edges {
        node {
          id
          type
          description
          initiator {
            name
          }
          actions {
            type
            context {
              field
              type
              values
            }
          }
          created_at
          last_execution_date
          completed
          task_expected_number
          task_processed_number
          errors {
            id
            timestamp
            message
          }
          ... on ListTask {
            task_ids
            scope
          }
          ... on QueryTask {
            task_filters
            task_search
            scope
          }
          work {
            id
            connector {
              name
            }
            user {
              name
            }
            completed_time
            received_time
            tracking {
              import_expected_number
              import_processed_number
            }
            messages {
              timestamp
              message
            }
            errors {
              timestamp
              message
            }
            status
            timestamp
            draft_context  
          }
        }
      }
    }
  }
`;
const TasksList = ({ data, options }) => {
  const classes = useStyles();
  const { t_i18n, nsdt, n } = useFormatter();
  const [displayMessages, setDisplayMessages] = useState(false);
  const [displayErrors, setDisplayErrors] = useState(false);
  const [messages, setMessages] = useState([]);
  const [errors, setErrors] = useState([]);
  const { backgroundTasks } = useFragment(TasksListFragment, data);
  const handleCloseMessages = () => {
    setDisplayMessages(false);
    setMessages([]);
  };

  const handleOpenErrors = (err) => {
    setDisplayErrors(true);
    setErrors(err);
  };

  const handleCloseErrors = () => {
    setDisplayErrors(false);
    setErrors([]);
  };

  const handleDeleteTask = (taskId) => {
    commitMutation({
      mutation: tasksListTaskDeletionMutation,
      variables: {
        id: taskId,
      },
      updater: (store) => {
        if (options) {
          deleteNode(store, 'Pagination_backgroundTasks', options, taskId);
        }
      },
      onCompleted: () => {
        MESSAGING$.notifySuccess(t_i18n('The task has been deleted'));
      },
    });
  };

  const tasks = backgroundTasks?.edges ?? [];
  return (
    <div>
      {tasks.length === 0 && (
        <Paper
          classes={{ root: classes.paper }}
          variant="outlined"
          style={{ marginBottom: 20 }}
        >
          <div
            style={{
              display: 'table',
              height: '100%',
              width: '100%',
            }}
          >
            <span
              style={{
                display: 'table-cell',
                verticalAlign: 'middle',
                textAlign: 'center',
              }}
            >
              {t_i18n('No task')}
            </span>
          </div>
        </Paper>
      )}
      {tasks.map((taskEdge) => {
        const task = taskEdge.node;
        let status = '';
        if (task.completed) {
          status = 'complete';
        } else if (task.task_processed_number > 0) {
          status = 'provisioning';
        } else {
          status = 'wait';
        }
        if (task.work) {
          if (task.work.status === 'wait' || task.work.status === 'progress') {
            status = 'processing';
          }
        }
        let filters = null;
        let listIds = '';
        if (task.task_filters) {
          filters = isFilterFormatCorrect(task.task_filters)
            ? deserializeFilterGroupForFrontend(task.task_filters)
            : convertFiltersFromOldFormat(task.task_filters);
        } else if (task.task_ids) {
          listIds = truncate(R.join(', ', task.task_ids), 60);
        }
        const lastTaskExecutionDate = task.work ? task.work.completed_time : task.last_execution_date;
        const taskWorkProcessedNumber = task.work?.tracking?.import_processed_number ?? 0;
        const taskWorkExpectedNumber = task.work?.tracking?.import_expected_number ?? 0;
        const progressNumberDisplay = task.work ? ` ${taskWorkProcessedNumber}/${taskWorkExpectedNumber}` : '';
        const provisioningNumberDisplay = task.work && (task.work.status === 'wait' || task.work.status === 'progress')
          ? ` (Provisioning: ${task.task_processed_number}/${task.task_expected_number})`
          : '';
        const progressFullText = `${t_i18n('Progress')}${progressNumberDisplay}${provisioningNumberDisplay}`;
        let progressValue = 0;
        if (task.work) {
          if (task.work.status === 'complete') {
            progressValue = 100;
          } else if (task.work.status === 'wait') {
            progressValue = 0;
          } else if (taskWorkExpectedNumber) {
            progressValue = Math.round((100 * (taskWorkProcessedNumber)) / (taskWorkExpectedNumber));
          } else {
            progressValue = 0;
          }
        } else {
          progressValue = 100;
        }
        const taskErrors = [...task.errors, ...(task.work?.errors ?? [])];
        return (
          <Paper
            key={task.id}
            classes={{ root: classes.paper }}
            variant="outlined"
            style={{ marginBottom: 20 }}
          >
            <Grid container={true} spacing={3}>
              <Grid item xs={5}>
                <Grid container={true} spacing={1}>
                  {task.description && (
                    <Grid item xs={12}>
                      <Typography variant="h3" gutterBottom={true}>
                        {`${t_i18n('Description')}: ${task.description}`}
                      </Typography>
                    </Grid>
                  )}
                  <Grid item xs={12}>
                    <Typography variant="h3" gutterBottom={true}>
                      {t_i18n('Targeted entities')} ({n(task.task_expected_number)})
                    </Typography>
                    {task.task_search && (
                      <span>
                        <Chip
                          classes={{ root: classes.filter }}
                          label={(
                            <div>
                              <strong>{t_i18n('Search')}</strong>:{' '}
                              {task.task_search}
                            </div>
                          )}
                        />
                        <Chip
                          classes={{ root: classes.operator }}
                          label={t_i18n('AND')}
                        />
                      </span>
                    )}
                    {task.type !== 'RULE'
                      && (isFilterGroupNotEmpty(filters)
                        ? (
                            <TasksFilterValueContainer
                              filters={filters}
                              entityTypes={['Stix-Core-Object', 'stix-core-relationship', 'Notification', 'User']}
                            />
                          )
                        : (
                            <Chip
                              classes={{ root: classes.filter }}
                              label={(
                                <div>
                                  <strong>{t_i18n('List of entities')}</strong>:{' '}
                                  {listIds}
                                </div>
                              )}
                            />
                          )
                      )
                    }
                    {task.type === 'RULE' && (
                      <Chip
                        classes={{ root: classes.filter }}
                        label={<div>{t_i18n('All rule targets')}</div>}
                      />
                    )}
                  </Grid>
                  <Grid item xs={12}>
                    <Typography variant="h3" gutterBottom={true}>
                      {t_i18n('Actions')}
                    </Typography>
                    {task.type === 'RULE' && (
                      <Chip
                        classes={{ root: classes.operator }}
                        label={<div>{t_i18n('APPLY RULE')}</div>}
                      />
                    )}
                    {task.actions
                      && R.map(
                        (action) => (
                          <div key={task.actions.indexOf(action)}>
                            <Chip
                              classes={{ root: classes.operator }}
                              label={action.type}
                            />
                            {action.context && (
                              <Chip
                                classes={{ root: classes.filter }}
                                label={(
                                  <div>
                                    {action.context.field && (
                                      <span>
                                        <strong>
                                          {t_i18n(action.context.field)}
                                        </strong>
                                        :{' '}
                                      </span>
                                    )}
                                    {truncate(
                                      R.join(
                                        ', ',
                                        action.context.values || [],
                                      ),
                                      80,
                                    )}
                                  </div>
                                )}
                              />
                            )}
                          </div>
                        ),
                        task.actions,
                      )}
                  </Grid>
                </Grid>
              </Grid>
              <Grid item xs={7}>
                <Grid container={true} spacing={3}>
                  <Grid item xs={2}>
                    <Typography variant="h3" gutterBottom={true}>
                      {t_i18n('Initiator')}
                    </Typography>
                    <Tooltip title={task.initiator?.name}>
                      {truncate(task.initiator?.name, 15)}
                    </Tooltip>
                  </Grid>
                  <Grid item xs={2}>
                    <Typography variant="h3" gutterBottom={true}>
                      {t_i18n('Task start time')}
                    </Typography>
                    {nsdt(task.created_at)}
                  </Grid>
                  <Grid item xs={2}>
                    <Typography variant="h3" gutterBottom={true}>
                      {task.completed
                        ? t_i18n('Task end time')
                        : t_i18n('Task last execution time')}
                    </Typography>
                    {nsdt(lastTaskExecutionDate)}
                  </Grid>
                  {(task.scope ?? task.type)
                    && (
                      <Grid item xs={2}>
                        <Typography variant="h3" gutterBottom={true}>
                          {t_i18n('Scope')}
                        </Typography>
                        <TaskScope scope={task.scope ?? task.type} label={t_i18n(task.scope ?? task.type)} />
                      </Grid>
                    )
                  }
                  <Grid item xs={2}>
                    <Typography variant="h3" gutterBottom={true}>
                      {t_i18n('Status')}
                    </Typography>
                    <TaskStatus status={status} label={t_i18n(status)} />
                  </Grid>
                  <Grid item xs={10}>
                    <Typography variant="h3" gutterBottom={true}>
                      {progressFullText}
                    </Typography>
                    <LinearProgress
                      classes={{ root: classes.progress }}
                      variant="determinate"
                      value={progressValue}
                    />
                  </Grid>
                </Grid>
                <br />
              </Grid>
              <Button
                style={{ position: 'absolute', right: 10, top: 10 }}
                variant={taskErrors.length > 0 ? 'primary' : 'secondary'}
                color="error"
                disabled={taskErrors.length === 0}
                onClick={() => handleOpenErrors(taskErrors)}
                size="small"
              >
                {taskErrors.length} {t_i18n('errors')}
              </Button>
              {task.scope // if task.scope exists = it is list task or a query task
                ? (
                    <Button
                      style={{ position: 'absolute', right: 10, bottom: 10 }}
                      variant="secondary"
                      onClick={() => handleDeleteTask(task.id)}
                      size="small"
                    >
                      <Delete fontSize="small" />
                  &nbsp;&nbsp;{t_i18n('Delete')}
                    </Button>
                  )
                : (
                    <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
                      <Button
                        style={{ position: 'absolute', right: 10, bottom: 10 }}
                        variant="secondary"
                        onClick={() => handleDeleteTask(task.id)}
                        size="small"
                      >
                        <Delete fontSize="small" />
                    &nbsp;&nbsp;{t_i18n('Delete')}
                      </Button>
                    </Security>
                  )
              }
            </Grid>
          </Paper>
        );
      })}
      <Dialog
        slotProps={{ paper: { elevation: 1 } }}
        open={displayMessages}
        keepMounted={true}
        slots={{ transition: Transition }}
        onClose={handleCloseMessages}
        fullScreen={true}
      >
        <DialogContent>
          <DialogContentText>
            <TableContainer component={Paper}>
              <Table className={classes.table} aria-label="simple table">
                <TableHead>
                  <TableRow>
                    <TableCell>{t_i18n('Timestamp')}</TableCell>
                    <TableCell>{t_i18n('Message')}</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {messages.map((message) => (
                    <TableRow key={message.timestamp}>
                      <TableCell>{nsdt(message.timestamp)}</TableCell>
                      <TableCell>{message.message}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button
            onClick={handleCloseMessages}
          >
            {t_i18n('Close')}
          </Button>
        </DialogActions>
      </Dialog>
      <Dialog
        slotProps={{ paper: { elevation: 1 } }}
        open={displayErrors}
        keepMounted={true}
        slots={{ transition: Transition }}
        onClose={handleCloseErrors}
        fullScreen={true}
      >
        <DialogContent>
          <DialogContentText>
            <TableContainer component={Paper}>
              <Table className={classes.table} aria-label="simple table">
                <TableHead>
                  <TableRow>
                    <TableCell>{t_i18n('Timestamp')}</TableCell>
                    <TableCell>{t_i18n('Message')}</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {errors.map((error) => (
                    <TableRow key={error.timestamp}>
                      <TableCell>{nsdt(error.timestamp)}</TableCell>
                      <TableCell>{error.message}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseErrors}>
            {t_i18n('Close')}
          </Button>
        </DialogActions>
      </Dialog>
    </div>
  );
};

export default TasksList;
