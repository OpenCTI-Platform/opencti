import React, { useState } from 'react';
import * as R from 'ramda';
import { graphql, useFragment } from 'react-relay';
import Grid from '@mui/material/Grid';
import Typography from '@mui/material/Typography';
import LinearProgress from '@mui/material/LinearProgress';
import Paper from '@mui/material/Paper';
import Button from '@mui/material/Button';
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

const useStyles = makeStyles((theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
    position: 'relative',
  },
  progress: {
    borderRadius: 5,
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
    ) {
      edges {
        node {
          id
          type
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
        }
      }
    }
  }
`;
const TasksList = ({ data }) => {
  const classes = useStyles();
  const { t, nsdt, n } = useFormatter();
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
      onCompleted: () => {
        MESSAGING$.notifySuccess('The task has been deleted');
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
            {t('No task')}
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
          status = 'progress';
        } else {
          status = 'wait';
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
        return (
          <Paper
            key={task.id}
            classes={{ root: classes.paper }}
            variant="outlined"
            style={{ marginBottom: 20 }}
          >
            <Grid container={true} spacing={3}>
              <Grid item={true} xs={5}>
                <Grid container={true} spacing={1}>
                  <Grid item={true} xs={12}>
                    <Typography variant="h3" gutterBottom={true}>
                      {t('Targeted entities')} ({n(task.task_expected_number)}
                      )
                    </Typography>
                    {task.task_search && (
                    <span>
                      <Chip
                        classes={{ root: classes.filter }}
                        label={
                          <div>
                            <strong>{t('Search')}</strong>:{' '}
                            {task.task_search}
                          </div>
                            }
                      />
                      <Chip
                        classes={{ root: classes.operator }}
                        label={t('AND')}
                      />
                    </span>
                    )}
                    {task.type !== 'RULE'
                        && (isFilterGroupNotEmpty(filters)
                          ? <TasksFilterValueContainer
                              filters={filters}
                            />
                          : (
                            <Chip
                              classes={{ root: classes.filter }}
                              label={
                                <div>
                                  <strong>{t('List of entities')}</strong>:{' '}
                                  {listIds}
                                </div>
                              }
                            />
                          )
                        )
                      }
                    {task.type === 'RULE' && (
                    <Chip
                      classes={{ root: classes.filter }}
                      label={<div>{t('All rule targets')}</div>}
                    />
                    )}
                  </Grid>
                  <Grid item={true} xs={12}>
                    <Typography variant="h3" gutterBottom={true}>
                      {t('Actions')}
                    </Typography>
                    {task.type === 'RULE' && (
                    <Chip
                      classes={{ root: classes.operator }}
                      label={<div>{t('APPLY RULE')}</div>}
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
                                  label={
                                    <div>
                                      {action.context.field && (
                                        <span>
                                          <strong>
                                            {action.context.field}
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
                                  }
                                />
                              )}
                            </div>
                          ),
                          task.actions,
                        )}
                  </Grid>
                </Grid>
              </Grid>
              <Grid item={true} xs={7}>
                <Grid container={true} spacing={3}>
                  <Grid item={true} xs={2}>
                    <Typography variant="h3" gutterBottom={true}>
                      {t('Initiator')}
                    </Typography>
                    {task.initiator?.name}
                  </Grid>
                  <Grid item={true} xs={2}>
                    <Typography variant="h3" gutterBottom={true}>
                      {t('Task start time')}
                    </Typography>
                    {nsdt(task.created_at)}
                  </Grid>
                  <Grid item={true} xs={2}>
                    <Typography variant="h3" gutterBottom={true}>
                      {task.completed
                        ? t('Task end time')
                        : t('Task last execution time')}
                    </Typography>
                    {nsdt(task.last_execution_date)}
                  </Grid>
                  {(task.scope ?? task.type)
                      && <Grid item={true} xs={2}>
                        <Typography variant="h3" gutterBottom={true}>
                          {t('Scope')}
                        </Typography>
                        <TaskScope scope={task.scope ?? task.type} label={t(task.scope ?? task.type)} />
                      </Grid>
                    }
                  <Grid item={true} xs={2}>
                    <Typography variant="h3" gutterBottom={true}>
                      {t('Status')}
                    </Typography>
                    <TaskStatus status={status} label={t(status)} />
                  </Grid>
                  <Grid item={true} xs={10}>
                    <Typography variant="h3" gutterBottom={true}>
                      {t('Progress')}
                    </Typography>
                    <LinearProgress
                      classes={{ root: classes.progress }}
                      variant="determinate"
                      value={
                          // eslint-disable-next-line no-nested-ternary
                          task.task_expected_number === 0
                            ? 0
                            : task.completed
                              ? 100
                              : Math.round(
                                (task.task_processed_number
                                  / task.task_expected_number)
                                  * 100,
                              )
                        }
                    />
                  </Grid>
                </Grid>
              </Grid>
              <Button
                style={{ position: 'absolute', right: 10, top: 10 }}
                variant="contained"
                color="secondary"
                onClick={() => handleOpenErrors(task.errors)}
                size="small"
              >
                {task.errors.length} {t('errors')}
              </Button>
              {task.scope // if task.scope exists = it is list task or a query task
                ? <Button
                    style={{ position: 'absolute', right: 10, bottom: 10 }}
                    variant="outlined"
                    onClick={() => handleDeleteTask(task.id)}
                    size="small"
                  >
                  <Delete fontSize="small"/>
                  &nbsp;&nbsp;{t('Delete')}
                </Button>
                : <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
                  <Button
                    style={{ position: 'absolute', right: 10, bottom: 10 }}
                    variant="outlined"
                    onClick={() => handleDeleteTask(task.id)}
                    size="small"
                  >
                    <Delete fontSize="small" />
                    &nbsp;&nbsp;{t('Delete')}
                  </Button>
                </Security>
              }
            </Grid>
          </Paper>
        );
      })}
      <Dialog
        PaperProps={{ elevation: 1 }}
        open={displayMessages}
        keepMounted={true}
        TransitionComponent={Transition}
        onClose={handleCloseMessages}
        fullScreen={true}
      >
        <DialogContent>
          <DialogContentText>
            <TableContainer component={Paper}>
              <Table className={classes.table} aria-label="simple table">
                <TableHead>
                  <TableRow>
                    <TableCell>{t('Timestamp')}</TableCell>
                    <TableCell>{t('Message')}</TableCell>
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
            color="primary"
          >
            {t('Close')}
          </Button>
        </DialogActions>
      </Dialog>
      <Dialog
        PaperProps={{ elevation: 1 }}
        open={displayErrors}
        keepMounted={true}
        TransitionComponent={Transition}
        onClose={handleCloseErrors}
        fullScreen={true}
      >
        <DialogContent>
          <DialogContentText>
            <TableContainer component={Paper}>
              <Table className={classes.table} aria-label="simple table">
                <TableHead>
                  <TableRow>
                    <TableCell>{t('Timestamp')}</TableCell>
                    <TableCell>{t('Message')}</TableCell>
                    <TableCell>{t('Source')}</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {errors.map((error) => (
                    <TableRow key={error.timestamp}>
                      <TableCell>{nsdt(error.timestamp)}</TableCell>
                      <TableCell>{error.message}</TableCell>
                      <TableCell>{error.source}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseErrors} color="primary">
            {t('Close')}
          </Button>
        </DialogActions>
      </Dialog>
    </div>
  );
};

export default TasksList;
