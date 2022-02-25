import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { graphql, createRefetchContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
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
import { interval } from 'rxjs';
import { Delete } from 'mdi-material-ui';
import Chip from '@mui/material/Chip';
import TaskStatus from '../../../../components/TaskStatus';
import inject18n from '../../../../components/i18n';
import { FIVE_SECONDS } from '../../../../utils/Time';
import { truncate } from '../../../../utils/String';
import { commitMutation, MESSAGING$ } from '../../../../relay/environment';
import Security, {
  KNOWLEDGE_KNUPDATE_KNDELETE,
} from '../../../../utils/Security';

const interval$ = interval(FIVE_SECONDS);

const styles = (theme) => ({
  container: {
    margin: 0,
  },
  editButton: {
    position: 'fixed',
    bottom: 30,
    right: 230,
  },
  gridContainer: {
    marginBottom: 20,
  },
  title: {
    float: 'left',
    textTransform: 'uppercase',
  },
  popover: {
    float: 'right',
    marginTop: '-13px',
  },
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
    position: 'relative',
  },
  card: {
    width: '100%',
    marginBottom: 20,
    borderRadius: 6,
    position: 'relative',
  },
  chip: {
    height: 30,
    float: 'left',
    margin: '0 10px 10px 0',
    backgroundColor: '#607d8b',
  },
  number: {
    fontWeight: 600,
    fontSize: 18,
  },
  progress: {
    borderRadius: 5,
    height: 10,
  },
  chipValue: {
    margin: 0,
  },
  filter: {
    margin: '5px 10px 5px 0',
  },
  operator: {
    fontFamily: 'Consolas, monaco, monospace',
    backgroundColor: theme.palette.background.accent,
    margin: '5px 10px 5px 0',
  },
});

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

export const tasksListTaskDeletionMutation = graphql`
  mutation TasksListTaskDeletionMutation($id: ID!) {
    deleteTask(id: $id)
  }
`;

class TasksListComponent extends Component {
  constructor(props) {
    super(props);
    this.state = {
      displayMessages: false,
      displayErrors: false,
      messages: [],
      errors: [],
    };
  }

  componentDidMount() {
    this.subscription = interval$.subscribe(() => {
      this.props.relay.refetch(this.props.options);
    });
  }

  componentWillUnmount() {
    this.subscription.unsubscribe();
  }

  handleOpenMessages(messages) {
    this.setState({ displayMessages: true, messages });
  }

  handleCloseMessages() {
    this.setState({ displayMessages: false, messages: [] });
  }

  handleOpenErrors(errors) {
    this.setState({ displayErrors: true, errors });
  }

  handleCloseErrors() {
    this.setState({ displayErrors: false, errors: [] });
  }

  // eslint-disable-next-line class-methods-use-this
  handleDeleteTask(taskId) {
    commitMutation({
      mutation: tasksListTaskDeletionMutation,
      variables: {
        id: taskId,
      },
      onCompleted: () => {
        MESSAGING$.notifySuccess('The task has been deleted');
      },
    });
  }

  render() {
    const { classes, data, t, nsdt, n } = this.props;
    const tasks = R.pathOr([], ['tasks', 'edges'], data);
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
            filters = JSON.parse(task.task_filters);
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
                        && (filters ? (
                          R.map((currentFilter) => {
                            const label = `${truncate(
                              t(`filter_${currentFilter[0]}`),
                              20,
                            )}`;
                            const values = (
                              <span>
                                {R.map(
                                  (o) => (
                                    <span key={o.value}>
                                      {o.value && o.value.length > 0
                                        ? truncate(o.value, 15)
                                        : t('No label')}{' '}
                                      {R.last(currentFilter[1]).value
                                        !== o.value && <code>OR</code>}{' '}
                                    </span>
                                  ),
                                  currentFilter[1],
                                )}
                              </span>
                            );
                            return (
                              <span key={currentFilter[0]}>
                                <Chip
                                  classes={{ root: classes.filter }}
                                  label={
                                    <div>
                                      <strong>{label}</strong>: {values}
                                    </div>
                                  }
                                />
                                {R.last(R.toPairs(filters))[0]
                                  !== currentFilter[0] && (
                                  <Chip
                                    classes={{ root: classes.operator }}
                                    label={t('AND')}
                                  />
                                )}
                              </span>
                            );
                          }, R.toPairs(filters))
                        ) : (
                          <Chip
                            classes={{ root: classes.filter }}
                            label={
                              <div>
                                <strong>{t('List of entities')}</strong>:{' '}
                                {listIds}
                              </div>
                            }
                          />
                        ))}
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
                <Grid item={true} xs={5}>
                  <Grid container={true} spacing={3}>
                    <Grid item={true} xs={3}>
                      <Typography variant="h3" gutterBottom={true}>
                        {t('Initiator')}
                      </Typography>
                      {task.initiator?.name}
                    </Grid>
                    <Grid item={true} xs={3}>
                      <Typography variant="h3" gutterBottom={true}>
                        {t('Task start time')}
                      </Typography>
                      {nsdt(task.created_at)}
                    </Grid>
                    <Grid item={true} xs={3}>
                      <Typography variant="h3" gutterBottom={true}>
                        {task.completed
                          ? t('Task end time')
                          : t('Task last execution time')}
                      </Typography>
                      {nsdt(task.last_execution_date)}
                    </Grid>
                    <Grid item={true} xs={3}>
                      <Typography variant="h3" gutterBottom={true}>
                        {t('Status')}
                      </Typography>
                      <TaskStatus status={status} label={t(status)} />
                    </Grid>
                    <Grid item={true} xs={12}>
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
                  onClick={this.handleOpenErrors.bind(this, task.errors)}
                  size="small"
                >
                  {task.errors.length} {t('errors')}
                </Button>
                <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
                  <Button
                    style={{ position: 'absolute', right: 10, bottom: 10 }}
                    variant="outlined"
                    onClick={this.handleDeleteTask.bind(this, task.id)}
                    size="small"
                  >
                    <Delete fontSize="small" />
                    &nbsp;&nbsp;{t('Delete')}
                  </Button>
                </Security>
              </Grid>
            </Paper>
          );
        })}
        <Dialog
          PaperProps={{ elevation: 1 }}
          open={this.state.displayMessages}
          keepMounted={true}
          TransitionComponent={Transition}
          onClose={this.handleCloseMessages.bind(this)}
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
                    {this.state.messages.map((message) => (
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
              onClick={this.handleCloseMessages.bind(this)}
              color="primary"
            >
              {t('Close')}
            </Button>
          </DialogActions>
        </Dialog>
        <Dialog
          PaperProps={{ elevation: 1 }}
          open={this.state.displayErrors}
          keepMounted={true}
          TransitionComponent={Transition}
          onClose={this.handleCloseErrors.bind(this)}
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
                    {this.state.errors.map((error) => (
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
            <Button onClick={this.handleCloseErrors.bind(this)} color="primary">
              {t('Close')}
            </Button>
          </DialogActions>
        </Dialog>
      </div>
    );
  }
}

TasksListComponent.propTypes = {
  data: PropTypes.object,
  options: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export const tasksListQuery = graphql`
  query TasksListQuery(
    $count: Int
    $orderBy: TasksOrdering
    $orderMode: OrderingMode
    $filters: [TasksFiltering]
  ) {
    ...TasksList_data
      @arguments(
        count: $count
        orderBy: $orderBy
        orderMode: $orderMode
        filters: $filters
      )
  }
`;

const TasksList = createRefetchContainer(
  TasksListComponent,
  {
    data: graphql`
      fragment TasksList_data on Query
      @argumentDefinitions(
        count: { type: "Int" }
        orderBy: { type: "TasksOrdering", defaultValue: created_at }
        orderMode: { type: "OrderingMode", defaultValue: desc }
        filters: { type: "[TasksFiltering]" }
      ) {
        tasks(
          first: $count
          orderBy: $orderBy
          orderMode: $orderMode
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
              }
              ... on QueryTask {
                task_filters
                task_search
              }
            }
          }
        }
      }
    `,
  },
  tasksListQuery,
);

export default R.compose(inject18n, withStyles(styles))(TasksList);
