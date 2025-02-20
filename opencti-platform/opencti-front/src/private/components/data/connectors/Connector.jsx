import React, { useEffect, useState } from 'react';
import * as PropTypes from 'prop-types';
import { createRefetchContainer, graphql } from 'react-relay';
import Grid from '@mui/material/Grid';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import Chip from '@mui/material/Chip';
import { interval } from 'rxjs';
import Tooltip from '@mui/material/Tooltip';
import IconButton from '@mui/material/IconButton';
import { InformationOutline } from 'mdi-material-ui';
import { DeleteOutlined, DeleteSweepOutlined, PlaylistRemoveOutlined } from '@mui/icons-material';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import { makeStyles, useTheme } from '@mui/styles';
import { Link, useNavigate } from 'react-router-dom';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import { ListItemButton } from '@mui/material';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Alert from '@mui/material/Alert';
import UpdateIcon from '@mui/icons-material/Update';
import Filters from '../../common/lists/Filters';
import ItemBoolean from '../../../../components/ItemBoolean';
import { useFormatter } from '../../../../components/i18n';
import { getConnectorAvailableFilterKeys, getConnectorFilterEntityTypes, getConnectorOnlyContextualStatus, getConnectorTriggerStatus } from '../../../../utils/Connector';
import { deserializeFilterGroupForFrontend, isFilterGroupNotEmpty, serializeFilterGroupForBackend } from '../../../../utils/filters/filtersUtils';
import useFiltersState from '../../../../utils/filters/useFiltersState';
import { FIVE_SECONDS } from '../../../../utils/Time';
import Security from '../../../../utils/Security';
import useGranted, { MODULES_MODMANAGE, SETTINGS_SETACCESSES } from '../../../../utils/hooks/useGranted';
import { commitMutation, MESSAGING$, QueryRenderer } from '../../../../relay/environment';
import ConnectorWorks, { connectorWorksQuery } from './ConnectorWorks';
import FilterIconButton from '../../../../components/FilterIconButton';
import Loader from '../../../../components/Loader';
import ItemCopy from '../../../../components/ItemCopy';
import Transition from '../../../../components/Transition';
import ItemIcon from '../../../../components/ItemIcon';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';

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
    marginTop: theme.spacing(1),
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
    orderBy: 'created_at',
    orderMode: 'asc',
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

  const theme = useTheme();
  const userHasSettingsCapability = useGranted([SETTINGS_SETACCESSES]);
  const connectorStateConverted = connector.connector_state ? JSON.parse(connector.connector_state) : null;
  const checkLastRunExistingInState = connectorStateConverted && Object.hasOwn(connectorStateConverted, 'last_run');
  const checkLastRunIsNumber = checkLastRunExistingInState && Number.isFinite(connectorStateConverted.last_run);
  const lastRunConverted = checkLastRunIsNumber && new Date(connectorStateConverted.last_run * 1000);

  const isBuffering = () => {
    return connector.connector_info?.queue_messages_size > connector.connector_info?.queue_threshold;
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
                <PlaylistRemoveOutlined/>
              </IconButton>
            </Tooltip>
            <Tooltip title={t_i18n('Clear all works')}>
              <IconButton
                onClick={handleOpenClearWorks}
                aria-haspopup="true"
                color="primary"
                size="large"
              >
                <DeleteSweepOutlined/>
              </IconButton>
            </Tooltip>
            <Tooltip title={t_i18n('Clear this connector')}>
              <IconButton
                onClick={handleOpenDelete}
                aria-haspopup="true"
                color="primary"
                disabled={connector.active || connector.built_in}
                size="large"
              >
                <DeleteOutlined/>
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
        <Grid item xs={6}>
          <Typography variant="h4" gutterBottom={true}>
            {t_i18n('Basic information')}
          </Typography>
          <Paper classes={{ root: classes.paper }} className={'paper-for-grid'} variant="outlined">
            <Grid container={true} spacing={3}>
              <Grid item xs={6}>
                <Typography variant="h3" gutterBottom={true}>
                  {t_i18n('Type')}
                </Typography>
                <Chip
                  key={connector.connector_type}
                  classes={{ root: classes.chip }}
                  label={connector.connector_type}
                />
              </Grid>
              <Grid item xs={6}>
                <Typography variant="h3" gutterBottom={true}>
                  {t_i18n('Last update')}
                </Typography>
                {nsdt(connector.updated_at)}
              </Grid>
              <Grid item xs={6}>
                <Typography variant="h3" gutterBottom={true}>
                  {t_i18n('Only contextual')}
                </Typography>
                <ItemBoolean
                  status={connectorOnlyContextualStatus.status}
                  label={connectorOnlyContextualStatus.label}
                />
              </Grid>
              <Grid item xs={6}>
                <Typography variant="h3" gutterBottom={true}>
                  {t_i18n('Automatic trigger')}
                </Typography>
                <ItemBoolean
                  status={connectorTriggerStatus.status}
                  label={connectorTriggerStatus.label}
                />
              </Grid>
              <Grid item xs={connectorFiltersEnabled ? 6 : 12}>
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
                <Grid item xs={6}>
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
              <Security needs={[SETTINGS_SETACCESSES]}>
                <Grid item xs={6}>
                  <Typography variant="h3" gutterBottom={true}>
                    {t_i18n('Associated user')}
                  </Typography>
                  {connector.connector_user ? (
                    <ListItemButton
                      key={connector.connector_user.id}
                      dense={true}
                      divider={true}
                      component={Link}
                      to={`/dashboard/settings/accesses/users/${connector.connector_user.id}`}
                    >
                      <ListItemIcon>
                        <ItemIcon type="user" color={theme.palette.primary.main} />
                      </ListItemIcon>
                      <ListItemText primary={connector.connector_user.name}/>
                    </ListItemButton>
                  ) : (
                    <FieldOrEmpty source={connector.connector_user}></FieldOrEmpty>
                  )}
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="h3" gutterBottom={true}>
                    {t_i18n('Max confidence level')}
                  </Typography>
                  {connector.connector_user ? (
                    <FieldOrEmpty source={connector.connector_user?.effective_confidence_level.max_confidence}>
                      {connector.connector_user.effective_confidence_level.max_confidence}
                    </FieldOrEmpty>
                  ) : (
                    <FieldOrEmpty source={connector.connector_user}></FieldOrEmpty>
                  )}
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="h3" gutterBottom={true}>
                    {t_i18n("User's roles")}
                  </Typography>
                  {connector.connector_user ? (
                    <FieldOrEmpty source={connector.connector_user.roles ?? []}>
                      <List>
                        {(connector.connector_user.roles ?? []).map((role) => (userHasSettingsCapability ? (
                          <ListItemButton
                            key={role?.id}
                            dense={true}
                            divider={true}
                            component={Link}
                            to={`/dashboard/settings/accesses/roles/${role?.id}`}
                          >
                            <ListItemIcon>
                              <ItemIcon type="Role" />
                            </ListItemIcon>
                            <ListItemText primary={role?.name} />
                          </ListItemButton>
                        ) : (
                          <ListItem key={role?.id} dense={true} divider={true}>
                            <ListItemIcon>
                              <ItemIcon type="Role" />
                            </ListItemIcon>
                            <ListItemText primary={role?.name} />
                          </ListItem>
                        )))}
                      </List>
                    </FieldOrEmpty>
                  ) : (
                    <FieldOrEmpty source={connector.connector_user}></FieldOrEmpty>
                  )}
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="h3" gutterBottom={true}>
                    {t_i18n("User's groups")}
                  </Typography>
                  {connector.connector_user ? (
                    <FieldOrEmpty source={connector.connector_user.groups?.edges}>
                      <List>
                        {(connector.connector_user.groups?.edges ?? []).map((groupEdge) => (userHasSettingsCapability ? (
                          <ListItemButton
                            key={groupEdge?.node.id}
                            dense={true}
                            divider={true}
                            component={Link}
                            to={`/dashboard/settings/accesses/groups/${groupEdge?.node.id}`}
                          >
                            <ListItemIcon>
                              <ItemIcon type="Group" />
                            </ListItemIcon>
                            <ListItemText primary={groupEdge?.node.name} />
                          </ListItemButton>
                        ) : (
                          <ListItem
                            key={groupEdge?.node.id}
                            dense={true}
                            divider={true}
                          >
                            <ListItemIcon>
                              <ItemIcon type="Group" />
                            </ListItemIcon>
                            <ListItemText primary={groupEdge?.node.name} />
                          </ListItem>
                        )))}
                      </List>
                    </FieldOrEmpty>
                  ) : (
                    <FieldOrEmpty source={connector.connector_user}></FieldOrEmpty>
                  )}
                </Grid>
                <Grid item xs={6}>
                  <Typography variant="h3" gutterBottom={true}>
                    {t_i18n("User's organizations")}
                  </Typography>
                  {connector.connector_user ? (
                    <FieldOrEmpty source={connector.connector_user.objectOrganization?.edges}>
                      <List>
                        {connector.connector_user.objectOrganization?.edges.map((organizationEdge) => (
                          <ListItemButton
                            key={organizationEdge.node.id}
                            dense={true}
                            divider={true}
                            component={Link}
                            to={`/dashboard/settings/accesses/organizations/${organizationEdge.node.id}`}
                          >
                            <ListItemIcon>
                              <ItemIcon
                                type="Organization"
                                color={
                                        (organizationEdge.node.authorized_authorities ?? []).includes(connector.connector_user.id)
                                          ? theme.palette.warning.main
                                          : theme.palette.primary.main
                                      }
                              />
                            </ListItemIcon>
                            <ListItemText primary={organizationEdge.node.name} />
                          </ListItemButton>
                        ))}
                      </List>
                    </FieldOrEmpty>
                  ) : (
                    <FieldOrEmpty source={connector.connector_user}></FieldOrEmpty>
                  )}
                </Grid>
              </Security>
            </Grid>

          </Paper>
        </Grid>
        <Grid item xs={6}>
          <Typography variant="h4" gutterBottom={true}>
            {t_i18n('Details')}
          </Typography>
          <Paper classes={{ root: classes.paper }} className={'paper-for-grid'} variant="outlined">
            <Grid container={true} spacing={3}>
              {connector.connector_info?.buffering && (
                <Grid item xs={12}>
                  <Alert severity="warning" icon={<UpdateIcon color={theme.palette.warning.main} />} style={{ alignItems: 'center' }}>
                    <strong>{t_i18n('Buffering: ')}</strong>
                    {t_i18n('Server ingestion is paused until the size of messages is reduced under max capacity')}
                  </Alert>
                </Grid>
              )}
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

              <Grid item xs={6}>
                {!connector.connector_info && (
                  connector.connector_state
                  && connectorStateConverted !== null
                  && checkLastRunExistingInState && checkLastRunIsNumber ? (
                    <>
                      <Typography variant="h3" gutterBottom={true}>
                        {t_i18n('Last run (from State)')}
                      </Typography>
                      <Typography variant="body1" gutterBottom={true}>
                        {nsdt(lastRunConverted)}
                      </Typography>
                    </>
                    ) : (
                      <>
                        <Typography variant="h3" gutterBottom={true}>
                          {t_i18n('Last run')}
                        </Typography>
                        <Typography variant="body1" gutterBottom={true}>
                          {t_i18n('Not provided')}
                        </Typography>
                      </>
                    )
                )}
                {connector.connector_info && (
                  // eslint-disable-next-line no-nested-ternary
                  connector.connector_info.last_run_datetime ? (
                    <>
                      <Typography variant="h3" gutterBottom={true}>
                        {t_i18n('Last run')}
                      </Typography>
                      <Typography variant="body1" gutterBottom={true}>
                        {nsdt(connector.connector_info?.last_run_datetime)}
                      </Typography>
                    </>
                  ) : (connector.connector_state
                      && connectorStateConverted !== null
                      && checkLastRunExistingInState && checkLastRunIsNumber
                    ? (<>
                      <Typography variant="h3" gutterBottom={true}>
                        {t_i18n('Last run (from State)')}
                      </Typography>
                      <Typography variant="body1" gutterBottom={true}>
                        {nsdt(lastRunConverted)}
                      </Typography>
                    </>)
                    : (<>
                      <Typography variant="h3" gutterBottom={true}>
                        {t_i18n('Last run')}
                      </Typography>
                      <Typography variant="body1" gutterBottom={true}>
                        {t_i18n('Not provided')}
                      </Typography>
                    </>)
                  )
                )}
              </Grid>

              <Grid item xs={6}>
                <Typography variant="h3" gutterBottom={true}>
                  {t_i18n('Next run')}
                </Typography>
                {connector.connector_info && (
                  // eslint-disable-next-line no-nested-ternary
                  connector.connector_info.run_and_terminate ? (
                    <Typography variant="body1" gutterBottom={true}>
                      {t_i18n('External schedule')}
                    </Typography>
                  ) : (
                    connector.connector_info.next_run_datetime !== null ? (
                      <Typography variant="body1" gutterBottom={true}>
                        {nsdt(connector.connector_info?.next_run_datetime)}
                      </Typography>
                    ) : (
                      <Typography variant="body1" gutterBottom={true}>
                        {t_i18n('Not provided')}
                      </Typography>
                    )
                  )
                )}
                {!connector.connector_info && (
                  <Typography variant="body1" gutterBottom={true}>
                    {t_i18n('Not provided')}
                  </Typography>
                )}
              </Grid>
              <Grid item xs={6}>
                <Typography variant="h3" gutterBottom={true} >
                  {t_i18n('Server capacity')}
                </Typography>
                {connector.connector_info && (connector.connector_info.queue_messages_size !== 0
                    || connector.connector_info.last_run_datetime) ? (
                      <FieldOrEmpty source={connector.connector_info?.queue_messages_size}>
                        <span style={isBuffering() ? { color: theme.palette.warning.main } : {}}>{connector.connector_info?.queue_messages_size.toFixed(2)}</span>
                        <span> / {connector.connector_info?.queue_threshold} Mo</span>
                      </FieldOrEmpty>
                  ) : (
                    <Typography variant="body1" gutterBottom={true}>
                      {t_i18n('Not provided')}
                    </Typography>
                  )
                }
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

      <QueryRenderer
        query={connectorWorksQuery}
        variables={optionsInProgress}
        render={({ props }) => {
          if (props) {
            return (
              <ConnectorWorks data={props} options={optionsInProgress} inProgress={true}/>
            );
          }
          return <Loader variant="inElement" />;
        }}
      />

      <QueryRenderer
        query={connectorWorksQuery}
        variables={optionsFinished}
        render={({ props }) => {
          if (props) {
            return <ConnectorWorks data={props} options={optionsFinished}/>;
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
        connector_user_id
        connector_user {
          id
          name
          roles {
            id
            name
          }
          groups {
            edges {
              node {
                id
                name
              }
            }
          }
          effective_confidence_level {
            max_confidence
          }
          objectOrganization {
            edges {
              node {
                id
                name
              }
            }
          }
        }
        connector_info {
          run_and_terminate
          buffering
          queue_threshold
          queue_messages_size
          next_run_datetime
          last_run_datetime
        }
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
