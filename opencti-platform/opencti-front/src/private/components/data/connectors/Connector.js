import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createRefetchContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import Typography from '@material-ui/core/Typography';
import Paper from '@material-ui/core/Paper';
import Button from '@material-ui/core/Button';
import Chip from '@material-ui/core/Chip';
import Slide from '@material-ui/core/Slide';
import { interval } from 'rxjs';
import Tooltip from '@material-ui/core/Tooltip';
import IconButton from '@material-ui/core/IconButton';
import { Delete, LayersRemove } from 'mdi-material-ui';
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

class ConnectorComponent extends Component {
  constructor(props) {
    super(props);
    this.state = {
      displayUpdate: false,
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

  // eslint-disable-next-line class-methods-use-this
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

  // eslint-disable-next-line class-methods-use-this
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
        { key: 'completed_number', values: ['0'], operator: 'gt' },
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
                  onClick={this.handleResetState.bind(this, connector.id)}
                  aria-haspopup="true"
                  color="primary"
                >
                  <LayersRemove />
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
        <Typography variant="h4" gutterBottom={true} style={{ marginTop: 35 }}>
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

export default compose(inject18n, withStyles(styles))(Connector);
