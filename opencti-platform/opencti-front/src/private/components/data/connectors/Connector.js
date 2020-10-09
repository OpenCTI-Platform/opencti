import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createRefetchContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import Typography from '@material-ui/core/Typography';
import LinearProgress from '@material-ui/core/LinearProgress';
import Paper from '@material-ui/core/Paper';
import Button from '@material-ui/core/Button';
import Chip from '@material-ui/core/Chip';
import Dialog from '@material-ui/core/Dialog';
import DialogContent from '@material-ui/core/DialogContent';
import DialogContentText from '@material-ui/core/DialogContentText';
import DialogActions from '@material-ui/core/DialogActions';
import Table from '@material-ui/core/Table';
import TableBody from '@material-ui/core/TableBody';
import TableCell from '@material-ui/core/TableCell';
import TableContainer from '@material-ui/core/TableContainer';
import TableHead from '@material-ui/core/TableHead';
import TableRow from '@material-ui/core/TableRow';
import Slide from '@material-ui/core/Slide';
import { interval } from 'rxjs';
import Tooltip from '@material-ui/core/Tooltip';
import IconButton from '@material-ui/core/IconButton';
import { Delete, RotateLeft } from 'mdi-material-ui';
import ItemStatus from '../../../../components/ItemStatus';
import ItemBoolean from '../../../../components/ItemBoolean';
import inject18n from '../../../../components/i18n';
import { FIVE_SECONDS } from '../../../../utils/Time';
import { truncate } from '../../../../utils/String';
import Security, { MODULES_MODMANAGE } from '../../../../utils/Security';
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

export const connectorResetStateMutation = graphql`
  mutation ConnectorResetStateMutation($id: ID!) {
    resetStateConnector(id: $id) {
      id
    }
  }
`;

export const connectorDeletionMutation = graphql`
  mutation ConnectorDeletionMutation($id: ID!) {
    deleteConnector(id: $id)
  }
`;

export const connectorWorkDeletionMutation = graphql`
  mutation ConnectorWorkDeletionMutation($id: ID!) {
    workEdit(id: $id) {
      delete
    }
  }
`;

class ConnectorComponent extends Component {
  constructor(props) {
    super(props);
    this.state = {
      displayUpdate: false,
      displayMessages: false,
      displayErrors: false,
      messages: [],
      errors: [],
    };
  }

  componentDidMount() {
    this.subscription = interval$.subscribe(() => {
      this.props.relay.refetch({ id: this.props.connector.id });
    });
  }

  componentWillUnmount() {
    this.subscription.unsubscribe();
  }

  handleOpenUpdate() {
    this.setState({ displayUpdate: true });
  }

  handleCloseUpdate() {
    this.setState({ displayUpdate: false });
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

  handleResetState(connectorId) {
    commitMutation({
      mutation: connectorResetStateMutation,
      variables: {
        id: connectorId,
      },
      onCompleted: () => {
        MESSAGING$.notifySuccess('The connector state has been reset');
      },
    });
  }

  handleDeleteWork(workId) {
    commitMutation({
      mutation: connectorWorkDeletionMutation,
      variables: {
        id: workId,
      },
      onCompleted: () => {
        MESSAGING$.notifySuccess('The work has been deleted');
      },
    });
  }

  handleDelete(connectorId) {
    commitMutation({
      mutation: connectorDeletionMutation,
      variables: {
        id: connectorId,
      },
      onCompleted: () => {
        MESSAGING$.notifySuccess('The connector has been cleared');
      },
    });
  }

  render() {
    const {
      classes, connector, t, nsdt,
    } = this.props;
    return (
      <div className={classes.container}>
        <div>
          <Typography
            variant="h1"
            gutterBottom={true}
            classes={{ root: classes.title }}
          >
            {connector.name}
          </Typography>
          <div className={classes.popover}>
            <Security needs={[MODULES_MODMANAGE]}>
              <Tooltip title={t('Reset the connector state')}>
                <IconButton
                  onClick={this.handleResetState.bind(this, connector.id)}
                  aria-haspopup="true"
                  color="primary"
                >
                  <RotateLeft />
                </IconButton>
              </Tooltip>
              <Tooltip title={t('Clear this connector')}>
                <IconButton
                  onClick={this.handleDelete.bind(this, connector.id)}
                  aria-haspopup="true"
                  color="primary"
                  disabled={connector.active}
                >
                  <Delete />
                </IconButton>
              </Tooltip>
            </Security>
          </div>
          <div className="clearfix" />
        </div>
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
        >
          <Grid item={true} xs={6}>
            <Typography variant="h4" gutterBottom={true}>
              {t('Basic information')}
            </Typography>
            <Paper classes={{ root: classes.paper }} elevation={2}>
              <Grid container={true} spacing={3}>
                <Grid item={true} xs={6}>
                  <Typography variant="h3" gutterBottom={true}>
                    {t('Type')}
                  </Typography>
                  <Button
                    style={{ cursor: 'default' }}
                    variant="outlined"
                    color="secondary"
                  >
                    {connector.connector_type}
                  </Button>
                </Grid>
                <Grid item={true} xs={6}>
                  <Typography variant="h3" gutterBottom={true}>
                    {t('Last update')}
                  </Typography>
                  {nsdt(connector.updated_at)}
                </Grid>
                <Grid item={true} xs={6}>
                  <Typography variant="h3" gutterBottom={true}>
                    {t('Active')}
                  </Typography>
                  <ItemBoolean
                    status={connector.active}
                    label={connector.active ? t('TRUE') : t('FALSE')}
                  />
                </Grid>
                <Grid item={true} xs={6}>
                  <Typography variant="h3" gutterBottom={true}>
                    {t('Automatic')}
                  </Typography>
                  <ItemBoolean
                    status={connector.auto}
                    label={connector.auto ? t('TRUE') : t('FALSE')}
                  />
                </Grid>
                <Grid item={true} xs={12}>
                  <Typography variant="h3" gutterBottom={true}>
                    {t('Scope')}
                  </Typography>
                  {connector.connector_scope.map((scope) => (
                    <Chip
                      key={scope}
                      classes={{ root: classes.chip }}
                      label={scope}
                    />
                  ))}
                </Grid>
              </Grid>
            </Paper>
          </Grid>
          <Grid item={true} xs={6}>
            <Typography variant="h4" gutterBottom={true}>
              {t('Details')}
            </Typography>
            <Paper classes={{ root: classes.paper }} elevation={2}>
              <Grid container={true} spacing={3}>
                <Grid item={true} xs={12}>
                  <Typography variant="h3" gutterBottom={true}>
                    {t('State')}
                  </Typography>
                  <pre>{connector.connector_state}</pre>
                </Grid>
                <Grid item={true} xs={6}>
                  <Typography variant="h3" gutterBottom={true}>
                    {t('Listen queue')}
                  </Typography>
                  <pre>{connector.config.listen}</pre>
                </Grid>
                <Grid item={true} xs={6}>
                  <Typography variant="h3" gutterBottom={true}>
                    {t('Push queue')}
                  </Typography>
                  <pre>{connector.config.push}</pre>
                </Grid>
              </Grid>
            </Paper>
          </Grid>
        </Grid>
        <Typography variant="h4" gutterBottom={true} style={{ marginTop: 35 }}>
          {t('Works')}
        </Typography>
        {connector.works.map((work) => (
          <Paper
            key={work.id}
            classes={{ root: classes.paper }}
            elevation={2}
            style={{ marginBottom: 20 }}
          >
            <Grid container={true} spacing={3}>
              <Grid item={true} xs={5}>
                <Grid container={true} spacing={3}>
                  <Grid item={true} xs={6}>
                    <Typography variant="h3" gutterBottom={true}>
                      {t('Name')}
                    </Typography>
                    {truncate(work.name, 40)}
                    <Typography
                      variant="h3"
                      gutterBottom={true}
                      style={{ marginTop: 20 }}
                    >
                      {t('Received time')}
                    </Typography>
                    {nsdt(work.received_time)}
                  </Grid>
                  <Grid item={true} xs={6}>
                    <Typography variant="h3" gutterBottom={true}>
                      {t('Status')}
                    </Typography>
                    <ItemStatus status={work.status} label={t(work.status)} />
                    <Typography
                      variant="h3"
                      gutterBottom={true}
                      style={{ marginTop: 20 }}
                    >
                      {t('Processed time')}
                    </Typography>
                    {nsdt(work.processed_time)}
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
                      {work.import_processed_number}
                    </span>
                  </Grid>
                  <Grid item={true} xs={6}>
                    <Typography variant="h3" gutterBottom={true}>
                      {t('Total number of operations')}
                    </Typography>
                    <span className={classes.number}>
                      {work.import_expected_number}
                    </span>
                  </Grid>
                  <Grid item={true} xs={12}>
                    <Typography variant="h3" gutterBottom={true}>
                      {t('Progress')}
                    </Typography>
                    <LinearProgress
                      classes={{ root: classes.progress }}
                      variant="determinate"
                      value={Math.round(
                        (work.import_processed_number
                          / work.import_expected_number)
                          * 100,
                      )}
                    />
                  </Grid>
                </Grid>
              </Grid>
              <Grid item={true} xs={2}>
                <Button
                  style={{ float: 'right', marginLeft: 20 }}
                  variant="outlined"
                  color="secondary"
                  onClick={this.handleOpenErrors.bind(this, work.errors)}
                >
                  {work.errors.length} {t('errors')}
                </Button>
                <Button
                  style={{ float: 'right' }}
                  variant="outlined"
                  color="primary"
                  onClick={this.handleOpenMessages.bind(this, work.messages)}
                >
                  {work.messages.length} {t('messages')}
                </Button>
                <div className="clearfix" style={{ height: 30 }} />
                <Button
                  style={{ float: 'right' }}
                  onClick={this.handleDeleteWork.bind(this, work.id)}
                >
                  {t('Delete')}
                </Button>
              </Grid>
            </Grid>
          </Paper>
        ))}
        <Dialog
          open={this.state.displayMessages}
          keepMounted={true}
          TransitionComponent={Transition}
          onClose={this.handleCloseMessages.bind(this)}
          fullWidth={true}
          maxWidth="lg"
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
          open={this.state.displayErrors}
          keepMounted={true}
          TransitionComponent={Transition}
          onClose={this.handleCloseErrors.bind(this)}
          fullWidth={true}
          maxWidth="lg"
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
                    {this.state.errors.map((error) => (
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
            <Button onClick={this.handleCloseErrors.bind(this)} color="primary">
              {t('Close')}
            </Button>
          </DialogActions>
        </Dialog>
      </div>
    );
  }
}

ConnectorComponent.propTypes = {
  connector: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export const connectorQuery = graphql`
  query ConnectorQuery($id: String!) {
    connector(id: $id) {
      id
      name
      ...Connector_connector
    }
  }
`;

const Connector = createRefetchContainer(
  ConnectorComponent,
  {
    connector: graphql`
      fragment Connector_connector on Connector {
        id
        name
        active
        auto
        connector_type
        connector_scope
        connector_state
        updated_at
        created_at
        config {
          uri
          listen
          listen_exchange
          push
          push_exchange
        }
        works {
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
          import_expected_number
          import_last_processed
          import_processed_number
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
    `,
  },
  connectorQuery,
);

export default compose(inject18n, withStyles(styles))(Connector);
