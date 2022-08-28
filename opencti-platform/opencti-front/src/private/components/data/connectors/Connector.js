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
import Slide from '@mui/material/Slide';
import { interval } from 'rxjs';
import Tooltip from '@mui/material/Tooltip';
import IconButton from '@mui/material/IconButton';
import { Delete, LayersRemove } from 'mdi-material-ui';
import { DeleteSweepOutlined } from '@mui/icons-material';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import { withRouter } from 'react-router-dom';
import ItemBoolean from '../../../../components/ItemBoolean';
import inject18n from '../../../../components/i18n';
import { FIVE_SECONDS } from '../../../../utils/Time';
import Security, { MODULES_MODMANAGE } from '../../../../utils/Security';
import {
  commitMutation,
  MESSAGING$,
  QueryRenderer,
} from '../../../../relay/environment';
import ConnectorWorks, { connectorWorksQuery } from './ConnectorWorks';
import { truncate } from '../../../../utils/String';
import Loader from '../../../../components/Loader';

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
    backgroundColor: theme.palette.background.accent,
    color: theme.palette.text.primary,
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
        MESSAGING$.notifySuccess('The connector state has been reset');
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
        this.props.history.push('/dashboard/data/connectors');
      },
    });
  }

  render() {
    const { classes, connector, t, nsdt } = this.props;
    const optionsInProgress = {
      count: 50,
      filters: [
        { key: 'connector_id', values: [connector.id] },
        { key: 'status', values: ['wait', 'progress'] },
      ],
    };
    const optionsFinished = {
      count: 50,
      filters: [
        { key: 'connector_id', values: [connector.id] },
        { key: 'status', values: ['complete'] },
      ],
    };
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
          <ItemBoolean
            status={connector.active}
            label={connector.active ? t('Active') : t('Inactive')}
          />
          <div className={classes.popover}>
            <Security needs={[MODULES_MODMANAGE]}>
              <Tooltip title={t('Reset the connector state')}>
                <IconButton
                  onClick={this.handleOpenResetState.bind(this, connector.id)}
                  aria-haspopup="true"
                  color="primary"
                  size="large"
                >
                  <LayersRemove />
                </IconButton>
              </Tooltip>
              <Tooltip title={t('Clear all works')}>
                <IconButton
                  onClick={this.handleOpenClearWorks.bind(this, connector.id)}
                  aria-haspopup="true"
                  color="primary"
                  size="large"
                >
                  <DeleteSweepOutlined />
                </IconButton>
              </Tooltip>
              <Tooltip title={t('Clear this connector')}>
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
        </div>
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
        >
          <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
            <Typography variant="h4" gutterBottom={true}>
              {t('Basic information')}
            </Typography>
            <Paper classes={{ root: classes.paper }} variant="outlined">
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
                    {t('Only contextual')}
                  </Typography>
                  <ItemBoolean
                    status={
                      connector.connector_type === 'INTERNAL_ENRICHMENT'
                      || connector.connector_type === 'INTERNAL_IMPORT_FILE'
                        ? connector.auto
                        : null
                    }
                    label={connector.only_contextual ? t('Yes') : t('No')}
                  />
                </Grid>
                <Grid item={true} xs={6}>
                  <Typography variant="h3" gutterBottom={true}>
                    {t('Automatic trigger')}
                  </Typography>
                  <ItemBoolean
                    status={
                      connector.connector_type === 'INTERNAL_ENRICHMENT'
                      || connector.connector_type === 'INTERNAL_IMPORT_FILE'
                        ? connector.auto
                        : null
                    }
                    label={connector.auto ? t('Yes') : t('No')}
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
          <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
            <Typography variant="h4" gutterBottom={true}>
              {t('Details')}
            </Typography>
            <Paper classes={{ root: classes.paper }} variant="outlined">
              <Grid container={true} spacing={3}>
                <Grid item={true} xs={12}>
                  <Typography variant="h3" gutterBottom={true}>
                    {t('State')}
                  </Typography>
                  <pre>{truncate(connector.connector_state, 200)}</pre>
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
        <Dialog
          PaperProps={{ elevation: 1 }}
          open={this.state.displayDelete}
          keepMounted={true}
          TransitionComponent={Transition}
          onClose={this.handleCloseDelete.bind(this)}
        >
          <DialogContent>
            <DialogContentText>
              {t('Do you want to delete this connector?')}
            </DialogContentText>
          </DialogContent>
          <DialogActions>
            <Button
              onClick={this.handleCloseDelete.bind(this)}
              disabled={this.state.deleting}
            >
              {t('Cancel')}
            </Button>
            <Button
              color="secondary"
              onClick={this.submitDelete.bind(this)}
              disabled={this.state.deleting}
            >
              {t('Delete')}
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
              {t('Do you want to reset the state of this connector?')}
            </DialogContentText>
          </DialogContent>
          <DialogActions>
            <Button
              onClick={this.handleCloseResetState.bind(this)}
              disabled={this.state.resetting}
            >
              {t('Cancel')}
            </Button>
            <Button
              onClick={this.submitResetState.bind(this)}
              color="secondary"
              disabled={this.state.resetting}
            >
              {t('Reset')}
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
              {t('Do you want to clear the works of this connector?')}
            </DialogContentText>
          </DialogContent>
          <DialogActions>
            <Button
              onClick={this.handleCloseClearWorks.bind(this)}
              disabled={this.state.clearing}
            >
              {t('Cancel')}
            </Button>
            <Button
              onClick={this.submitClearWorks.bind(this)}
              color="secondary"
              disabled={this.state.clearing}
            >
              {t('Clear')}
            </Button>
          </DialogActions>
        </Dialog>
        <Typography variant="h4" gutterBottom={true} style={{ marginTop: 60 }}>
          {t('In progress works')}
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
          {t('Completed works')}
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
      </div>
    );
  }
}

ConnectorComponent.propTypes = {
  connector: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
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
        updated_at
        created_at
        config {
          listen
          listen_exchange
          push
          push_exchange
        }
      }
    `,
  },
  connectorQuery,
);

export default compose(inject18n, withRouter, withStyles(styles))(Connector);
