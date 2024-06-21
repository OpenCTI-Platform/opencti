import React, { useEffect, useState } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createRefetchContainer } from 'react-relay';
import Grid from '@mui/material/Grid';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import Chip from '@mui/material/Chip';
import { interval } from 'rxjs';
import Tooltip from '@mui/material/Tooltip';
import IconButton from '@mui/material/IconButton';
import { Delete, InformationOutline, LayersRemove } from 'mdi-material-ui';
import { DeleteSweepOutlined } from '@mui/icons-material';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import { makeStyles } from '@mui/styles';
import { useNavigate } from 'react-router-dom';
import Filters from '../../common/lists/Filters';
import ItemBoolean from '../../../../components/ItemBoolean';
import { useFormatter } from '../../../../components/i18n';
import { getConnectorAvailableFilterKeys, getConnectorFilterEntityTypes, getConnectorOnlyContextualStatus, getConnectorTriggerStatus } from '../../../../utils/Connector';
import { deserializeFilterGroupForFrontend, isFilterGroupNotEmpty, serializeFilterGroupForBackend } from '../../../../utils/filters/filtersUtils';
import useFiltersState from '../../../../utils/filters/useFiltersState';
import { FIVE_SECONDS } from '../../../../utils/Time';
import Security from '../../../../utils/Security';
import { MODULES_MODMANAGE } from '../../../../utils/hooks/useGranted';
import { commitMutation, MESSAGING$, QueryRenderer } from '../../../../relay/environment';
import ConnectorWorks, { connectorWorksQuery } from './ConnectorWorks';
import FilterIconButton from '../../../../components/FilterIconButton';
import Loader from '../../../../components/Loader';
import ItemCopy from '../../../../components/ItemCopy';
import Transition from '../../../../components/Transition';

const interval$ = interval(FIVE_SECONDS);

const useStyles = makeStyles((theme) => ({
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
  chip: {
    height: 30,
    float: 'left',
    margin: '0 10px 10px 0',
    borderRadius: 4,
    backgroundColor: theme.palette.background.accent,
    color: theme.palette.text.primary,
  },
}));

export const connectorUpdateTriggerMutation = graphql`
  mutation ConnectorUpdateTriggerMutation($id: ID!, $input: [EditInput]!) {
    updateConnectorTrigger(id: $id, input: $input) {
      id
      active
      auto
      only_contextual
      connector_trigger_filters
    }
  }
`;

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

const ConnectorComponent = ({ connector, relay }) => {
  const { t_i18n, nsdt } = useFormatter();
  const navigate = useNavigate();
  const classes = useStyles();
  const connectorTriggerStatus = getConnectorTriggerStatus(connector);
  const connectorOnlyContextualStatus = getConnectorOnlyContextualStatus(connector);
  // connector trigger filters
  const connectorFilters = deserializeFilterGroupForFrontend(connector.connector_trigger_filters);
  const connectorFiltersEnabled = connector.connector_type === 'INTERNAL_ENRICHMENT';
  const connectorFiltersScope = getConnectorFilterEntityTypes(connector);
  const connectorAvailableFilterKeys = getConnectorAvailableFilterKeys(connector);
  const [filters, helpers] = useFiltersState(connectorFilters);

  const [displayDelete, setDisplayDelete] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [displayResetState, setDisplayResetState] = useState(false);
  const [resetting, setResetting] = useState(false);
  const [displayClearWorks, setDisplayClearWorks] = useState(false);
  const [clearing, setClearing] = useState(false);

  useEffect(() => {
    const subscription = interval$.subscribe(() => {
      relay.refetch({ id: connector.id });
    });
    return () => subscription.unsubscribe();
  }, []);

  const submitUpdateConnectorTrigger = (variables) => {
    commitMutation({
      mutation: connectorUpdateTriggerMutation,
      variables,
      onCompleted: () => {
        MESSAGING$.notifySuccess('The connector trigger filters have been updated.');
      },
    });
  };

  useEffect(() => {
    if ((!filters || !isFilterGroupNotEmpty(filters)) && !connector.connector_trigger_filters) {
      return; // do nothing, nothing has changed
    }
    const jsonFilters = serializeFilterGroupForBackend(filters);
    if (!isFilterGroupNotEmpty(deserializeFilterGroupForFrontend(jsonFilters)) && !connector.connector_trigger_filters) {
      return; // do nothing, nothing has changed
    }
    if (connectorFiltersEnabled && connector.connector_trigger_filters !== jsonFilters) {
      // submit update only if filters have changed, otherwise do nothing
      const variables = {
        id: connector.id,
        input: { key: 'connector_trigger_filters', value: jsonFilters },
      };
      submitUpdateConnectorTrigger(variables);
    }
  }, [filters]);

  const handleOpenDelete = () => {
    setDisplayDelete(true);
  };

  const handleCloseDelete = () => {
    setDisplayDelete(false);
  };

  const handleOpenResetState = () => {
    setDisplayResetState(true);
  };

  const handleCloseResetState = () => {
    setDisplayResetState(false);
  };

  const handleOpenClearWorks = () => {
    setDisplayClearWorks(true);
  };

  const handleCloseClearWorks = () => {
    setDisplayClearWorks(false);
  };

  const submitResetState = () => {
    setResetting(true);
    commitMutation({
      mutation: connectorResetStateMutation,
      variables: {
        id: connector.id,
      },
      onCompleted: () => {
        MESSAGING$.notifySuccess('The connector state has been reset and messages queue has been purged');
        setResetting(false);
        setDisplayResetState(false);
      },
    });
  };

  const submitClearWorks = () => {
    setClearing(true);
    commitMutation({
      mutation: connectorWorkDeleteMutation,
      variables: {
        connectorId: connector.id,
      },
      onCompleted: () => {
        MESSAGING$.notifySuccess('The connector works have been cleared');
        setClearing(false);
        setDisplayClearWorks(false);
      },
    });
  };

  const submitDelete = () => {
    setDeleting(true);
    commitMutation({
      mutation: connectorDeletionMutation,
      variables: {
        id: connector.id,
      },
      onCompleted: () => {
        handleCloseDelete();
        navigate('/dashboard/data/ingestion/connectors');
      },
    });
  };

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
                onClick={handleOpenResetState}
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
                onClick={handleOpenClearWorks}
                aria-haspopup="true"
                color="primary"
                size="large"
              >
                <DeleteSweepOutlined />
              </IconButton>
            </Tooltip>
            <Tooltip title={t_i18n('Clear this connector')}>
              <IconButton
                onClick={handleOpenDelete}
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
                  status={connectorOnlyContextualStatus.status}
                  label={connectorOnlyContextualStatus.label}
                />
              </Grid>
              <Grid item={true} xs={6}>
                <Typography variant="h3" gutterBottom={true}>
                  {t_i18n('Automatic trigger')}
                </Typography>
                <ItemBoolean
                  status={connectorTriggerStatus.status}
                  label={connectorTriggerStatus.label}
                />
              </Grid>
              <Grid item={true} xs={connectorFiltersEnabled ? 6 : 12}>
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
              {connectorFiltersEnabled && (
                <Grid item={true} xs={6}>
                  <Typography variant="h3" gutterBottom={true}>
                    <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
                      <span>{t_i18n('Trigger filters')}</span>
                      <Tooltip title={t_i18n('Trigger filters can be used to trigger automatically this connector on entities matching the filters and scope.')}>
                        <InformationOutline fontSize="small" color="primary" />
                      </Tooltip>
                    </Box>
                  </Typography>
                  <Box sx={{ display: 'flex', gap: 1, paddingTop: '4px' }}>
                    <Filters
                      availableFilterKeys={connectorAvailableFilterKeys}
                      helpers={helpers}
                      searchContext={{ entityTypes: connectorFiltersScope }}
                    />
                  </Box>
                  {filters && (
                    <Box sx={{ overflow: 'hidden' }}>
                      <FilterIconButton
                        filters={filters}
                        helpers={helpers}
                        styleNumber={2}
                        searchContext={{ entityTypes: connectorFiltersScope }}
                        entityTypes={connectorFiltersScope}
                      />
                    </Box>
                  )}
                </Grid>
              )}
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
        open={displayDelete}
        keepMounted={true}
        TransitionComponent={Transition}
        onClose={handleCloseDelete}
      >
        <DialogContent>
          <DialogContentText>
            {t_i18n('Do you want to delete this connector?')}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button
            onClick={handleCloseDelete}
            disabled={deleting}
          >
            {t_i18n('Cancel')}
          </Button>
          <Button
            color="secondary"
            onClick={submitDelete}
            disabled={deleting}
          >
            {t_i18n('Delete')}
          </Button>
        </DialogActions>
      </Dialog>
      <Dialog
        PaperProps={{ elevation: 1 }}
        open={displayResetState}
        keepMounted={true}
        TransitionComponent={Transition}
        onClose={handleCloseResetState}
      >
        <DialogContent>
          <DialogContentText>
            {t_i18n('Do you want to reset the state and purge messages queue of this connector?')}
          </DialogContentText>
          <DialogContentText>
            {t_i18n('Number of messages: ') + connector.connector_queue_details.messages_number}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button
            onClick={handleCloseResetState}
            disabled={resetting}
          >
            {t_i18n('Cancel')}
          </Button>
          <Button
            onClick={submitResetState}
            color="secondary"
            disabled={resetting}
          >
            {t_i18n('Reset')}
          </Button>
        </DialogActions>
      </Dialog>
      <Dialog
        PaperProps={{ elevation: 1 }}
        open={displayClearWorks}
        keepMounted={true}
        TransitionComponent={Transition}
        onClose={handleCloseClearWorks}
      >
        <DialogContent>
          <DialogContentText>
            {t_i18n('Do you want to clear the works of this connector?')}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button
            onClick={handleCloseClearWorks}
            disabled={clearing}
          >
            {t_i18n('Cancel')}
          </Button>
          <Button
            onClick={submitClearWorks}
            color="secondary"
            disabled={clearing}
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
};

ConnectorComponent.propTypes = {
  connector: PropTypes.object,
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
        connector_trigger_filters
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

export default Connector;
