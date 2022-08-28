import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, pathOr, filter } from 'ramda';
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
import TaskStatus from '../../../../components/TaskStatus';
import inject18n from '../../../../components/i18n';
import { FIVE_SECONDS } from '../../../../utils/Time';
import { truncate } from '../../../../utils/String';
import { commitMutation, MESSAGING$ } from '../../../../relay/environment';

const interval$ = interval(FIVE_SECONDS);

const styles = () => ({
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
});

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

export const connectorWorksWorkDeletionMutation = graphql`
  mutation ConnectorWorksWorkDeletionMutation($id: ID!) {
    workEdit(id: $id) {
      delete
    }
  }
`;

class ConnectorWorksComponent extends Component {
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
  handleDeleteWork(workId) {
    commitMutation({
      mutation: connectorWorksWorkDeletionMutation,
      variables: {
        id: workId,
      },
      onCompleted: () => {
        MESSAGING$.notifySuccess('The work has been deleted');
      },
    });
  }

  render() {
    const { classes, data, t, nsdt } = this.props;
    const works = pathOr([], ['works', 'edges'], data);
    return (
      <div>
        {works.length === 0 && (
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
                {t('No work')}
              </span>
            </div>
          </Paper>
        )}
        {works.map((workEge) => {
          const work = workEge.node;
          const { tracking } = work;
          const errors = filter(
            (n) => !n.message.includes('MissingReferenceError'),
            work.errors,
          );
          return (
            <Paper
              key={work.id}
              classes={{ root: classes.paper }}
              variant="outlined"
              style={{ marginBottom: 20 }}
            >
              <Grid container={true} spacing={3}>
                <Grid item={true} xs={5}>
                  <Grid container={true} spacing={1}>
                    <Grid item={true} xs={6}>
                      <Typography variant="h3" gutterBottom={true}>
                        {t('Name')}
                      </Typography>
                      {truncate(work.name, 40)}
                    </Grid>
                    <Grid item={true} xs={6}>
                      <Typography variant="h3" gutterBottom={true}>
                        {t('Status')}
                      </Typography>
                      <TaskStatus status={work.status} label={t(work.status)} />
                    </Grid>
                    <Grid item={true} xs={6}>
                      <Typography
                        variant="h3"
                        gutterBottom={true}
                        style={{ marginTop: 20 }}
                      >
                        {t('Work start time')}
                      </Typography>
                      {nsdt(work.received_time)}
                    </Grid>
                    <Grid item={true} xs={6}>
                      <Typography
                        variant="h3"
                        gutterBottom={true}
                        style={{ marginTop: 20 }}
                      >
                        {t('Work end time')}
                      </Typography>
                      {work.completed_time ? nsdt(work.completed_time) : '-'}
                    </Grid>
                  </Grid>
                </Grid>
                <Grid item={true} xs={5}>
                  <Grid container={true} spacing={3}>
                    <Grid item={true} xs={6}>
                      <Typography variant="h3" gutterBottom={true}>
                        {t('Operations completed')}
                      </Typography>
                      <span className={classes.number}>
                        {work.status === 'wait'
                          ? '-'
                          : tracking?.import_processed_number ?? '-'}
                      </span>
                    </Grid>
                    <Grid item={true} xs={6}>
                      <Typography variant="h3" gutterBottom={true}>
                        {t('Total number of operations')}
                      </Typography>
                      <span className={classes.number}>
                        {work.status === 'wait'
                          ? '-'
                          : tracking?.import_expected_number ?? '-'}
                      </span>
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
                          tracking
                            ? tracking.import_expected_number === 0
                              ? 0
                              : Math.round(
                                (tracking.import_processed_number
                                    / tracking.import_expected_number)
                                    * 100,
                              )
                            : 0
                        }
                      />
                    </Grid>
                  </Grid>
                </Grid>
                <Button
                  style={{ position: 'absolute', right: 10, top: 10 }}
                  variant="contained"
                  color="secondary"
                  onClick={this.handleOpenErrors.bind(this, errors)}
                  size="small"
                >
                  {errors.length} {t('errors')}
                </Button>
                <Button
                  variant="outlined"
                  style={{ position: 'absolute', right: 10, bottom: 10 }}
                  onClick={this.handleDeleteWork.bind(this, work.id)}
                  size="small"
                >
                  <Delete fontSize="small" />
                  &nbsp;&nbsp;{t('Delete')}
                </Button>
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

ConnectorWorksComponent.propTypes = {
  data: PropTypes.object,
  options: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export const connectorWorksQuery = graphql`
  query ConnectorWorksQuery(
    $count: Int
    $orderBy: WorksOrdering
    $orderMode: OrderingMode
    $filters: [WorksFiltering]
  ) {
    ...ConnectorWorks_data
      @arguments(
        count: $count
        orderBy: $orderBy
        orderMode: $orderMode
        filters: $filters
      )
  }
`;

const ConnectorWorks = createRefetchContainer(
  ConnectorWorksComponent,
  {
    data: graphql`
      fragment ConnectorWorks_data on Query
      @argumentDefinitions(
        count: { type: "Int" }
        orderBy: { type: "WorksOrdering", defaultValue: timestamp }
        orderMode: { type: "OrderingMode", defaultValue: desc }
        filters: { type: "[WorksFiltering]" }
      ) {
        works(
          first: $count
          orderBy: $orderBy
          orderMode: $orderMode
          filters: $filters
        ) {
          edges {
            node {
              id
              name
              user {
                name
              }
              timestamp
              status
              event_source_id
              received_time
              processed_time
              completed_time
              tracking {
                import_expected_number
                import_processed_number
              }
              messages {
                timestamp
                message
                sequence
                source
              }
              errors {
                timestamp
                message
                sequence
                source
              }
            }
          }
        }
      }
    `,
  },
  connectorWorksQuery,
);

export default compose(inject18n, withStyles(styles))(ConnectorWorks);
