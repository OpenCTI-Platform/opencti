import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql, createRefetchContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Grid from '@mui/material/Grid';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import Button from '@mui/material/Button';
import Chip from '@mui/material/Chip';
import { interval } from 'rxjs';
import Tooltip from '@mui/material/Tooltip';
import IconButton from '@mui/material/IconButton';
import { Delete, LayersRemove } from 'mdi-material-ui';
import { DeleteSweepOutlined } from '@mui/icons-material';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import withRouter from '../../../../utils/compat-router/withRouter';
import ItemBoolean from '../../../../components/ItemBoolean';
import inject18n from '../../../../components/i18n';
import { FIVE_SECONDS } from '../../../../utils/Time';
import Security from '../../../../utils/Security';
import { MODULES_MODMANAGE } from '../../../../utils/hooks/useGranted';
import { commitMutation, MESSAGING$, QueryRenderer } from '../../../../relay/environment';
import ConnectorWorks, { connectorWorksQuery } from './ConnectorWorks';
import Loader from '../../../../components/Loader';
import ItemCopy from '../../../../components/ItemCopy';
import Transition from '../../../../components/Transition';

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
    marginRight: 30,
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
    borderRadius: 4,
  },
  card: {
    width: '100%',
    marginBottom: 20,
    borderRadius: 4,
    position: 'relative',
  },
  chip: {
    height: 30,
    float: 'left',
    margin: '0 10px 10px 0',
    borderRadius: 4,
    backgroundColor: theme.palette.background.accent,
    color: theme.palette.text.primary,
  },
  number: {
    fontWeight: 600,
    fontSize: 18,
  },
  progress: {
    borderRadius: 4,
    height: 10,
  },
});

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

export const connectorWorkDeleteMutation = graphql`
  mutation ConnectorWorkDeleteMutation($connectorId: String!) {
    workDelete(connectorId: $connectorId)
  }
`;

class ConnectorComponent extends Component {
  constructor(props) {
    super(props);
    this.state = {
      displayDelete: false,
      deleting: false,
      displayResetState: false,
      resetting: false,
      displayClearWorks: false,
      clearing: false,
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

  handleOpenDelete() {
    this.setState({ displayDelete: true });
  }

  handleCloseDelete() {
    this.setState({ displayDelete: false });
  }

  handleOpenResetState() {
    this.setState({ displayResetState: true });
  }

  handleCloseResetState() {
    this.setState({ displayResetState: false });
  }

  handleOpenClearWorks() {
    this.setState({ displayClearWorks: true });
  }

  handleCloseClearWorks() {
    this.setState({ displayClearWorks: false });
  }

  submitResetState() {
    this.setState({ resetting: true });
    commitMutation({
      mutation: connectorResetStateMutation,
      variables: {
        id: this.props.connector.id,
      },
      onCompleted: () => {
        MESSAGING$.notifySuccess('The connector state has been reset and messages queue has been purged');
        this.setState({ resetting: false, displayResetState: false });
      },
    });
  }

  submitClearWorks() {
    this.setState({ clearing: true });
    commitMutation({
      mutation: connectorWorkDeleteMutation,
      variables: {
        connectorId: this.props.connector.id,
      },
      onCompleted: () => {
        MESSAGING$.notifySuccess('The connector works have been cleared');
        this.setState({ clearing: false, displayClearWorks: false });
      },
    });
  }

  submitDelete() {
    this.setState({ deleting: true });
    commitMutation({
      mutation: connectorDeletionMutation,
      variables: {
        id: this.props.connector.id,
      },
      onCompleted: () => {
        this.handleCloseDelete();
        this.props.navigate('/dashboard/data/ingestion/connectors');
      },
    });
  }

  render() {
    const { classes, connector, t: t_i18n, nsdt } = this.props;
    const optionsInProgress = {
      count: 50,
      filters: {
        mode: 'and',
        filters: [
          { key: 'connector_id', values: [connector.id], operator: 'eq', mode: 'or' },
          { key: 'status', values: ['wait', 'progress'], operator: 'eq', mode: 'or' },
        ],
        filterGroups: [],
      },
    };
    const optionsFinished = {
      count: 50,
      filters: {
        mode: 'and',
        filters: [
          { key: 'connector_id', values: [connector.id], operator: 'eq', mode: 'or' },
          { key: 'status', values: ['complete'], operator: 'eq', mode: 'or' },
        ],
        filterGroups: [],
      },
    };
    return (
      <>
        <>
          <Typography
            variant="h1"
            gutterBottom={true}
            classes={{ root: classes.title }}
          >
            {connector.name}
          </Typography>
          <ItemBoolean
            status={connector.active}
            label={connector.active ? t_i18n('Active') : t_i18n('Inactive')}
          />
          <div className={classes.popover}>
            <Security needs={[MODULES_MODMANAGE]}>
              <Tooltip title={t_i18n('Reset the connector state')}>
                <IconButton
                  onClick={this.handleOpenResetState.bind(this, connector.id)}
                  aria-haspopup="true"
                  color="primary"
                  size="large"
                  disabled={connector.built_in}
                >
                  <LayersRemove />
                </IconButton>
              </Tooltip>
              <Tooltip title={t_i18n('Clear all works')}>
                <IconButton
                  onClick={this.handleOpenClearWorks.bind(this, connector.id)}
                  aria-haspopup="true"
                  color="primary"
                  size="large"
                >
                  <DeleteSweepOutlined />
                </IconButton>
              </Tooltip>
              <Tooltip title={t_i18n('Clear this connector')}>
                <IconButton
                  onClick={this.handleOpenDelete.bind(this, connector.id)}
                  aria-haspopup="true"
                  color="primary"
                  disabled={connector.active}
                  size="large"
                >
                  <Delete />
                </IconButton>
              </Tooltip>
            </Security>
          </div>
          <div className="clearfix" />
        </>
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
        >
          <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
            <Typography variant="h4" gutterBottom={true}>
              {t_i18n('Basic information')}
            </Typography>
            <Paper classes={{ root: classes.paper }} variant="outlined">
              <Grid container={true} spacing={3}>
                <Grid item={true} xs={6}>
                  <Typography variant="h3" gutterBottom={true}>
                    {t_i18n('Type')}
                  </Typography>
                  <Button
                    style={{ cursor: 'default' }}
                    variant="outlined"
                    color="primary"
                  >
                    {connector.connector_type}
                  </Button>
                </Grid>
                <Grid item={true} xs={6}>
                  <Typography variant="h3" gutterBottom={true}>
                    {t_i18n('Last update')}
                  </Typography>
                  {nsdt(connector.updated_at)}
                </Grid>
                <Grid item={true} xs={6}>
                  <Typography variant="h3" gutterBottom={true}>
                    {t_i18n('Only contextual')}
                  </Typography>
                  <ItemBoolean
                    status={
                      connector.connector_type === 'INTERNAL_ENRICHMENT'
                      || connector.connector_type === 'INTERNAL_IMPORT_FILE'
                        ? connector.auto
                        : null
                    }
                    label={connector.only_contextual ? t_i18n('Yes') : t_i18n('No')}
                  />
                </Grid>
                <Grid item={true} xs={6}>
                  <Typography variant="h3" gutterBottom={true}>
                    {t_i18n('Automatic trigger')}
                  </Typography>
                  <ItemBoolean
                    status={
                      connector.connector_type === 'INTERNAL_ENRICHMENT'
                      || connector.connector_type === 'INTERNAL_IMPORT_FILE'
                        ? connector.auto
                        : null
                    }
                    label={connector.auto ? t_i18n('Yes') : t_i18n('No')}
                  />
                </Grid>
                <Grid item={true} xs={12}>
                  <Typography variant="h3" gutterBottom={true}>
                    {t_i18n('Scope')}
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
          <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
            <Typography variant="h4" gutterBottom={true}>
              {t_i18n('Details')}
            </Typography>
            <Paper classes={{ root: classes.paper }} variant="outlined">
              <Grid container={true} spacing={3}>
                <Grid item={true} xs={12}>
                  <Typography variant="h3" gutterBottom={true}>
                    {t_i18n('State')}
                  </Typography>
                  <Tooltip title={connector.connector_state}>
                    <pre>
                      <ItemCopy
                        content={connector.connector_state}
                        limit={200}
                      />
                    </pre>
                  </Tooltip>
                </Grid>
                <Grid item={true} xs={6}>
                  <Typography variant="h3" gutterBottom={true}>
                    {t_i18n('Listen queue')}
                  </Typography>
                  <pre>{connector.config.listen}</pre>
                </Grid>
                <Grid item={true} xs={6}>
                  <Typography variant="h3" gutterBottom={true}>
                    {t_i18n('Push queue')}
                  </Typography>
                  <pre>{connector.config.push}</pre>
                </Grid>
              </Grid>
            </Paper>
          </Grid>
        </Grid>
        <Dialog
          PaperProps={{ elevation: 1 }}
          open={this.state.displayDelete}
          keepMounted={true}
          TransitionComponent={Transition}
          onClose={this.handleCloseDelete.bind(this)}
        >
          <DialogContent>
            <DialogContentText>
              {t_i18n('Do you want to delete this connector?')}
            </DialogContentText>
          </DialogContent>
          <DialogActions>
            <Button
              onClick={this.handleCloseDelete.bind(this)}
              disabled={this.state.deleting}
            >
              {t_i18n('Cancel')}
            </Button>
            <Button
              color="secondary"
              onClick={this.submitDelete.bind(this)}
              disabled={this.state.deleting}
            >
              {t_i18n('Delete')}
            </Button>
          </DialogActions>
        </Dialog>
        <Dialog
          PaperProps={{ elevation: 1 }}
          open={this.state.displayResetState}
          keepMounted={true}
          TransitionComponent={Transition}
          onClose={this.handleCloseResetState.bind(this)}
        >
          <DialogContent>
            <DialogContentText>
              {t_i18n('Do you want to reset the state and purge messages queue of this connector? ')}
            </DialogContentText>
            <DialogContentText>
              {t_i18n('Number of messages: ') + connector.connector_queue_details.messages_number}
            </DialogContentText>
          </DialogContent>
          <DialogActions>
            <Button
              onClick={this.handleCloseResetState.bind(this)}
              disabled={this.state.resetting}
            >
              {t_i18n('Cancel')}
            </Button>
            <Button
              onClick={this.submitResetState.bind(this)}
              color="secondary"
              disabled={this.state.resetting}
            >
              {t_i18n('Reset')}
            </Button>
          </DialogActions>
        </Dialog>
        <Dialog
          PaperProps={{ elevation: 1 }}
          open={this.state.displayClearWorks}
          keepMounted={true}
          TransitionComponent={Transition}
          onClose={this.handleCloseClearWorks.bind(this)}
        >
          <DialogContent>
            <DialogContentText>
              {t_i18n('Do you want to clear the works of this connector?')}
            </DialogContentText>
          </DialogContent>
          <DialogActions>
            <Button
              onClick={this.handleCloseClearWorks.bind(this)}
              disabled={this.state.clearing}
            >
              {t_i18n('Cancel')}
            </Button>
            <Button
              onClick={this.submitClearWorks.bind(this)}
              color="secondary"
              disabled={this.state.clearing}
            >
              {t_i18n('Clear')}
            </Button>
          </DialogActions>
        </Dialog>
        <Typography variant="h4" gutterBottom={true} style={{ marginTop: 60 }}>
          {t_i18n('In progress works')}
        </Typography>
        <QueryRenderer
          query={connectorWorksQuery}
          variables={optionsInProgress}
          render={({ props }) => {
            if (props) {
              return (
                <ConnectorWorks data={props} options={optionsInProgress} />
              );
            }
            return <Loader variant="inElement" />;
          }}
        />
        <Typography variant="h4" gutterBottom={true} style={{ marginTop: 35 }}>
          {t_i18n('Completed works')}
        </Typography>
        <QueryRenderer
          query={connectorWorksQuery}
          variables={optionsFinished}
          render={({ props }) => {
            if (props) {
              return <ConnectorWorks data={props} options={optionsFinished} />;
            }
            return <Loader variant="inElement" />;
          }}
        />
      </>
    );
  }
}

ConnectorComponent.propTypes = {
  connector: PropTypes.object,
  classes: PropTypes.object,
  t_i18n: PropTypes.func,
  navigate: PropTypes.func,
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
        only_contextual
        connector_type
        connector_scope
        connector_state
        connector_queue_details {
          messages_number
          messages_size
        }
        updated_at
        created_at
        config {
          listen
          listen_exchange
          push
          push_exchange
        }
        built_in
      }
    `,
  },
  connectorQuery,
);

export default compose(inject18n, withRouter, withStyles(styles))(Connector);
