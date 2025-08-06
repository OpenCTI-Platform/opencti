import React, { FunctionComponent, useEffect, useState } from 'react';
import { createRefetchContainer, graphql, RelayRefetchProp } from 'react-relay';
import Grid from '@mui/material/Grid';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import Chip from '@mui/material/Chip';
import { interval } from 'rxjs';
import Tooltip from '@mui/material/Tooltip';
import { InformationOutline } from 'mdi-material-ui';
import { DeleteOutlined, DeleteSweepOutlined, PlaylistRemoveOutlined } from '@mui/icons-material';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import { useTheme } from '@mui/styles';
import { Link, useNavigate } from 'react-router-dom';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import { ListItemButton } from '@mui/material';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Alert from '@mui/material/Alert';
import UpdateIcon from '@mui/icons-material/Update';
import ToggleButton from '@mui/material/ToggleButton';
import ToggleButtonGroup from '@mui/material/ToggleButtonGroup';
import DialogTitle from '@mui/material/DialogTitle';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import ManagedConnectorEdition from './ManagedConnectorEdition';
import DangerZoneBlock from '../../common/danger_zone/DangerZoneBlock';
import Filters from '../../common/lists/Filters';
import ItemBoolean from '../../../../components/ItemBoolean';
import { useFormatter } from '../../../../components/i18n';
import {
  useGetConnectorAvailableFilterKeys,
  useGetConnectorFilterEntityTypes,
  getConnectorOnlyContextualStatus,
  getConnectorTriggerStatus,
  useComputeConnectorStatus,
} from '../../../../utils/Connector';
import { deserializeFilterGroupForFrontend, isFilterGroupNotEmpty, serializeFilterGroupForBackend } from '../../../../utils/filters/filtersUtils';
import useFiltersState from '../../../../utils/filters/useFiltersState';
import { FIVE_SECONDS } from '../../../../utils/Time';
import Security from '../../../../utils/Security';
import useGranted, { MODULES_MODMANAGE, SETTINGS_SETACCESSES } from '../../../../utils/hooks/useGranted';
import { MESSAGING$, QueryRenderer } from '../../../../relay/environment';
import ConnectorWorks, { connectorWorksQuery } from './ConnectorWorks';
import FilterIconButton from '../../../../components/FilterIconButton';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import ItemCopy from '../../../../components/ItemCopy';
import Transition from '../../../../components/Transition';
import ItemIcon from '../../../../components/ItemIcon';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import DeleteDialog from '../../../../components/DeleteDialog';
import useDeletion from '../../../../utils/hooks/useDeletion';
import useSensitiveModifications from '../../../../utils/hooks/useSensitiveModifications';
import EditEntityControlledDial from '../../../../components/EditEntityControlledDial';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import type { Theme } from '../../../../components/Theme';
import { Connector_connector$data } from './__generated__/Connector_connector.graphql';
import { ConnectorUpdateTriggerMutation, EditInput } from './__generated__/ConnectorUpdateTriggerMutation.graphql';
import { ConnectorUpdateStatusMutation } from './__generated__/ConnectorUpdateStatusMutation.graphql';
import { ConnectorWorksQuery$variables, ConnectorWorksQuery$data } from './__generated__/ConnectorWorksQuery.graphql';

// Type extension for organization node with authorized_authorities
interface OrganizationNodeWithAuthorities {
  id: string;
  name: string;
  authorized_authorities?: ReadonlyArray<string>;
}

const interval$ = interval(FIVE_SECONDS);

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

const updateRequestedStatus = graphql`
  mutation ConnectorUpdateStatusMutation($input: RequestConnectorStatusInput!) {
    updateConnectorRequestedStatus(input: $input) {
      id
      manager_current_status
      manager_requested_status
    }
  }
`;

interface ConnectorComponentProps {
  connector: Connector_connector$data;
  relay: RelayRefetchProp;
}

const ConnectorComponent: FunctionComponent<ConnectorComponentProps> = ({ connector, relay }) => {
  const { t_i18n, nsdt } = useFormatter();
  const navigate = useNavigate();
  const theme = useTheme<Theme>();

  // Helper function to create connector configuration
  const getConnectorConfig = () => ({
    name: connector.name,
    active: connector.active ?? false,
    auto: connector.auto ?? false,
    only_contextual: connector.only_contextual ?? false,
    connector_trigger_filters: connector.connector_trigger_filters ?? '',
    connector_type: connector.connector_type ?? '',
    connector_scope: connector.connector_scope ?? [],
    connector_state: connector.connector_state ?? '',
  });

  const connectorConfig = getConnectorConfig();
  const connectorTriggerStatus = getConnectorTriggerStatus(connectorConfig);
  const connectorOnlyContextualStatus = getConnectorOnlyContextualStatus(connectorConfig);

  // connector trigger filters
  const connectorFilters = deserializeFilterGroupForFrontend(connector.connector_trigger_filters);
  const connectorFiltersEnabled = connector.connector_type === 'INTERNAL_ENRICHMENT';
  const connectorFiltersScope = useGetConnectorFilterEntityTypes(connectorConfig);
  const connectorAvailableFilterKeys = useGetConnectorAvailableFilterKeys(connectorConfig);
  const [filters, helpers] = useFiltersState(connectorFilters);

  const [displayResetState, setDisplayResetState] = useState(false);
  const [resetting, setResetting] = useState(false);
  const [displayClearWorks, setDisplayClearWorks] = useState(false);
  const [clearing, setClearing] = useState(false);
  const [editionOpen, setEditionOpen] = useState(false);
  const [tabValue, setTabValue] = useState(0);

  // API mutations - defined early to avoid use-before-define errors
  const [commitUpdateStatus] = useApiMutation<ConnectorUpdateStatusMutation>(updateRequestedStatus);
  const [commitResetState] = useApiMutation(connectorResetStateMutation);
  const [commitDeleteConnector] = useApiMutation(connectorDeletionMutation);
  const [commitClearWorks] = useApiMutation(connectorWorkDeleteMutation);
  const [commitUpdateConnectorTrigger] = useApiMutation<ConnectorUpdateTriggerMutation>(connectorUpdateTriggerMutation);

  useEffect(() => {
    const subscription = interval$.subscribe(() => {
      relay.refetch({ id: connector.id });
    });
    return () => subscription.unsubscribe();
  }, [connector.id, relay]);

  const submitUpdateConnectorTrigger = (variables: ConnectorUpdateTriggerMutation['variables']) => {
    commitUpdateConnectorTrigger({
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
        input: [{ key: 'connector_trigger_filters', value: [jsonFilters] }] as EditInput[],
      };
      submitUpdateConnectorTrigger(variables);
    }
  }, [filters, connector.id, connector.connector_trigger_filters, connectorFiltersEnabled]);

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
    commitResetState({
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
    commitClearWorks({
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

  const deletion = useDeletion({});
  const { setDeleting, handleOpenDelete, handleCloseDelete } = deletion;
  const submitDelete = () => {
    setDeleting(true);
    commitDeleteConnector({
      variables: {
        id: connector.id,
      },
      onCompleted: () => {
        handleCloseDelete();
        navigate('/dashboard/data/ingestion/connectors');
      },
    });
  };

  const optionsInProgress: ConnectorWorksQuery$variables = {
    count: 50,
    orderMode: 'asc',
    filters: {
      mode: 'and',
      filters: [
        { key: ['connector_id'], values: [connector.id] },
        { key: ['status'], values: ['wait', 'progress'] },
      ],
      filterGroups: [],
    },
  };
  const optionsFinished: ConnectorWorksQuery$variables = {
    count: 50,
    filters: {
      mode: 'and',
      filters: [
        { key: ['connector_id'], values: [connector.id] },
        { key: ['status'], values: ['complete'] },
      ],
      filterGroups: [],
    },
  };
  const filtersSearchContext = { entityTypes: connectorFiltersScope, connectorsScope: true };

  const userHasSettingsCapability = useGranted([SETTINGS_SETACCESSES]);
  const connectorStateConverted = connector.connector_state ? JSON.parse(connector.connector_state) : null;
  const checkLastRunExistingInState = connectorStateConverted && Object.prototype.hasOwnProperty.call(connectorStateConverted, 'last_run');
  const checkLastRunIsNumber = checkLastRunExistingInState && Number.isFinite(connectorStateConverted.last_run);
  const lastRunConverted = checkLastRunIsNumber && new Date(connectorStateConverted.last_run * 1000);

  const isBuffering = () => {
    return connector.connector_info ? connector.connector_info.queue_messages_size > connector.connector_info.queue_threshold : false;
  };

  const { isSensitive } = useSensitiveModifications('connector_reset');

  const computeConnectorStatus = useComputeConnectorStatus();

  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
  };

  // Component for Overview content
  const ConnectorOverview = () => (
    <>
      <Grid container={true} spacing={3} style={{ marginBottom: 20 }}>
        <Grid item xs={6}>
          <Typography variant="h4" gutterBottom={true}>
            {t_i18n('Basic information')}
          </Typography>
          <Paper style={{
            marginTop: theme.spacing(1),
            padding: '15px',
            borderRadius: 4,
          }} className={'paper-for-grid'} variant="outlined"
          >
            <Grid container={true} spacing={3}>
              <Grid item xs={6}>
                <Typography variant="h3" gutterBottom={true}>
                  {t_i18n('Type')}
                </Typography>
                <Chip
                  key={connector.connector_type}
                  style={{
                    height: 30,
                    float: 'left',
                    margin: '0 10px 10px 0',
                    borderRadius: 4,
                    backgroundColor: theme.palette.background.accent,
                    color: theme.palette.text?.primary,
                  }}
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
                {connector.connector_scope?.map((scope) => (
                  <Chip
                    key={scope}
                    style={{
                      height: 30,
                      float: 'left',
                      margin: '0 10px 10px 0',
                      borderRadius: 4,
                      backgroundColor: theme.palette.background.accent,
                      color: theme.palette.text?.primary,
                    }}
                    label={scope}
                  />
                ))}
              </Grid>
              {connectorFiltersEnabled && (
              <Grid item xs={6}>
                <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
                  <Typography variant="h3" gutterBottom={true}>
                    {t_i18n('Trigger filters')}
                  </Typography>
                  <Tooltip title={t_i18n('Trigger filters can be used to trigger automatically this connector on entities matching the filters and scope.')}>
                    <span>
                      <InformationOutline fontSize="small" color="primary" />
                    </span>
                  </Tooltip>
                </Box>
                <Box sx={{ display: 'flex', gap: 1, paddingTop: '4px' }}>
                  <Filters
                    availableFilterKeys={connectorAvailableFilterKeys}
                    helpers={helpers}
                    searchContext={filtersSearchContext}
                  />
                </Box>
                {filters && (
                  <Box sx={{ overflow: 'hidden' }}>
                    <FilterIconButton
                      filters={filters}
                      helpers={helpers}
                      styleNumber={2}
                      searchContext={filtersSearchContext}
                      entityTypes={connectorFiltersScope}
                    />
                  </Box>
                )}
              </Grid>
              )}
              <Security needs={[SETTINGS_SETACCESSES]}>
                <>
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
                        <ListItemText primary={connector.connector_user.name} />
                      </ListItemButton>
                    ) : (
                      <FieldOrEmpty source={connector.connector_user}>{null}</FieldOrEmpty>
                    )}
                  </Grid>
                  <Grid item xs={6}>
                    <Typography variant="h3" gutterBottom={true}>
                      {t_i18n('Max confidence level')}
                    </Typography>
                    {connector.connector_user ? (
                      <FieldOrEmpty source={connector.connector_user?.effective_confidence_level?.max_confidence}>
                        {connector.connector_user.effective_confidence_level?.max_confidence}
                      </FieldOrEmpty>
                    ) : (
                      <FieldOrEmpty source={connector.connector_user}>{null}</FieldOrEmpty>
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
                      <FieldOrEmpty source={connector.connector_user}>{null}</FieldOrEmpty>
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
                      <FieldOrEmpty source={connector.connector_user}>{null}</FieldOrEmpty>
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
                                  ((organizationEdge.node as OrganizationNodeWithAuthorities).authorized_authorities ?? []).includes(connector.connector_user?.id ?? '')
                                    ? theme.palette.dangerZone
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
                      <FieldOrEmpty source={connector.connector_user}>{null}</FieldOrEmpty>
                    )}
                  </Grid>
                </>
              </Security>
            </Grid>
          </Paper>
        </Grid>
        <Grid item xs={6}>
          <Typography variant="h4" gutterBottom={true}>
            {t_i18n('Details')}
          </Typography>
          <Paper style={{
            marginTop: theme.spacing(1),
            padding: '15px',
            borderRadius: 4,
          }} className={'paper-for-grid'} variant="outlined"
          >
            <Grid container={true} spacing={3}>
              {connector.connector_info?.buffering && (
              <Grid item xs={12}>
                <Alert severity="warning" icon={<UpdateIcon color="warning" />} style={{ alignItems: 'center' }}>
                  <div>
                    <strong>{t_i18n('Buffering: ')}</strong>
                    {t_i18n('Server ingestion is not accepting new work, waiting for current messages in ingestion to be processed until message count go back under threshold')}
                  </div>
                </Alert>
              </Grid>
              )}
              <Grid item={true} xs={12}>
                <Typography variant="h3" gutterBottom={true}>
                  {t_i18n('State')}
                </Typography>
                <Tooltip title={connector.connector_state || ''}>
                  <pre>
                    <ItemCopy
                      content={connector.connector_state || ''}
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
                    </>) : (connector.connector_state
                  && connectorStateConverted !== null
                  && checkLastRunExistingInState && checkLastRunIsNumber ? (<>
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
                <Typography variant="h3" gutterBottom={true}>
                  {t_i18n('Server capacity')}
                </Typography>
                {connector.connector_info && (connector.connector_info.queue_messages_size !== 0
                || connector.connector_info.last_run_datetime) ? (
                  <FieldOrEmpty source={connector.connector_info?.queue_messages_size}>
                    <span style={isBuffering() ? { color: theme.palette.dangerZone.main } : {}}>{connector.connector_info?.queue_messages_size.toFixed(2)}</span>
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
      <QueryRenderer
        query={connectorWorksQuery}
        variables={optionsInProgress}
        render={({ props }: { props: ConnectorWorksQuery$data | null }) => (
          <>
            {props ? (
              <ConnectorWorks data={props} options={[optionsInProgress]} inProgress={true} />
            ) : (
              <Loader variant={LoaderVariant.inElement} />
            )}
          </>
        )}
      />

      <QueryRenderer
        query={connectorWorksQuery}
        variables={optionsFinished}
        render={({ props }: { props: ConnectorWorksQuery$data | null }) => (
          <>
            {props ? (
              <ConnectorWorks data={props} options={[optionsFinished]} />
            ) : (
              <Loader variant={LoaderVariant.inElement} />
            )}
          </>
        )}
      />
    </>
  );

  // Component for Logs content
  const ConnectorLogs = () => (
    <Box sx={{ marginBottom: '20px' }}>
      <pre
        style={{
          height: '100%',
          overflowX: 'scroll',
          paddingBottom: theme.spacing(2),
          backgroundColor: theme.palette.background.paper,
          padding: theme.spacing(2),
          borderRadius: 4,
          border: `1px solid ${theme.palette.divider}`,
        }}
      >
        {connector.manager_connector_logs?.join('\n') || t_i18n('No logs available')}
      </pre>
    </Box>
  );

  return (
    <>
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          width: '100%',
          marginBottom: theme.spacing(2),
        }}
      >
        <Typography
          variant="h1"
          gutterBottom={true}
          style={{
            textTransform: 'uppercase',
            alignItems: 'center',
            display: 'flex',
            gap: theme.spacing(1),
            margin: 0,
          }}
        >
          {connector.name}
          <div style={{ display: 'inline-block' }}>
            {computeConnectorStatus(connector).render}
          </div>
        </Typography>
        <div style={{
          float: 'right',
          display: 'flex',
          alignItems: 'center',
          gap: theme.spacing(1),
        }}
        >
          <Security needs={[MODULES_MODMANAGE]}>
            <>
              {connector.is_managed && (
              <Button
                variant="contained"
                disabled={computeConnectorStatus(connector).processing}
                color={connector.manager_current_status === 'started' ? 'error' : 'primary'}
                onClick={() => commitUpdateStatus({
                  variables: {
                    input: {
                      id: connector.id,
                      status: connector.manager_current_status === 'started' ? 'stopping' : 'starting',
                    },
                  },
                })}
              >
                {t_i18n(connector.manager_current_status === 'started' ? 'Stop' : 'Start')}
              </Button>
              )}
              {isSensitive && (
                <div style={{ position: 'relative', display: 'inline-block' }}>
                  <DangerZoneBlock
                    type="connector_reset"
                    sx={{
                      root: { border: 'none', padding: 0, margin: 0 },
                      title: { position: 'absolute', zIndex: 1, left: 4, top: 9, fontSize: 8 },
                    }}
                  >
                    {({ disabled = false }: { disabled?: boolean }) => (
                      <Button
                        color="error"
                        variant="outlined"
                        disabled={disabled || !!connector.built_in}
                        onClick={handleOpenResetState}
                        style={{
                          minWidth: '6rem',
                        }}
                      >
                        <span style={{ zIndex: 2 }}>
                          {t_i18n('Reset')}
                        </span>
                      </Button>
                    )}
                  </DangerZoneBlock>
                </div>
              )}
              <ToggleButtonGroup
                size="small"
              >
                {!isSensitive && (
                  <Tooltip title={t_i18n('Reset the connector state')}>
                    <span>
                      <ToggleButton
                        onClick={handleOpenResetState}
                        aria-haspopup="true"
                        disabled={!!connector.built_in}
                        value={t_i18n('Reset')}
                      >
                        <PlaylistRemoveOutlined
                          color="primary"
                        />
                      </ToggleButton>
                    </span>
                  </Tooltip>
                )}
                <Tooltip title={t_i18n('Clear all works')}>
                  <span>
                    <ToggleButton
                      onClick={handleOpenClearWorks}
                      aria-haspopup="true"
                      value={t_i18n('Clear')}
                    >
                      <DeleteSweepOutlined
                        color="primary"
                      />
                    </ToggleButton>
                  </span>
                </Tooltip>
                <Tooltip title={t_i18n('Clear this connector')}>
                  <span>
                    <ToggleButton
                      onClick={handleOpenDelete}
                      aria-haspopup="true"
                      disabled={!!connector.active || !!connector.built_in}
                      value={t_i18n('Delete')}
                    >
                      <DeleteOutlined
                        color="primary"
                      />
                    </ToggleButton>
                  </span>
                </Tooltip>
              </ToggleButtonGroup>
              {connector.is_managed && (
                <EditEntityControlledDial
                  onOpen={() => setEditionOpen(true)}
                  variant='outlined'
                  style={{}}
                />
              )}
            </>
          </Security>
        </div>
      </div>
      {editionOpen
          && (<ManagedConnectorEdition connector={connector} onClose={() => setEditionOpen(false)} />)}

      {connector.is_managed ? (
        <>
          <Box
            sx={{
              borderBottom: 1,
              borderColor: 'divider',
              marginBottom: 3,
            }}
          >
            <Tabs value={tabValue} onChange={handleTabChange}>
              <Tab label={t_i18n('Overview')} />
              <Tab label={t_i18n('Logs')} />
            </Tabs>
          </Box>
          <Box>
            {tabValue === 0 && <ConnectorOverview />}
            {tabValue === 1 && <ConnectorLogs />}
          </Box>
        </>
      ) : (
        <ConnectorOverview />
      )}
      <DeleteDialog
        deletion={deletion}
        submitDelete={submitDelete}
        message={t_i18n('Do you want to delete this connector?')}
      />
      <Dialog
        slotProps={{ paper: { elevation: 1 } }}
        open={displayResetState}
        keepMounted={true}
        slots={{ transition: Transition }}
        onClose={handleCloseResetState}
      >
        <DialogTitle>
          {t_i18n('Are you sure?')}
        </DialogTitle>
        <DialogContent>
          <DialogContentText component="div">
            <Alert
              severity={isSensitive ? 'warning' : 'info'}
              variant="outlined"
              color={isSensitive ? 'dangerZone' : undefined}
              style={isSensitive ? {
                borderColor: theme.palette.dangerZone.main,
              } : {}}
            >
              <div>
                {t_i18n('Do you want to reset the state and purge messages queue of this connector?')}
                <br />
                {t_i18n('Number of messages: ') + connector.connector_queue_details.messages_number}
              </div>
            </Alert>
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
            color={isSensitive ? 'error' : 'secondary'}
            disabled={resetting}
          >
            {t_i18n('Confirm')}
          </Button>
        </DialogActions>
      </Dialog>
      <Dialog
        slotProps={{ paper: { elevation: 1 } }}
        open={displayClearWorks}
        keepMounted={true}
        slots={{ transition: Transition }}
        onClose={handleCloseClearWorks}
      >
        <DialogTitle>
          {t_i18n('Are you sure?')}
        </DialogTitle>
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
            {t_i18n('Confirm')}
          </Button>
        </DialogActions>
      </Dialog>

    </>
  );
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
        is_managed
        manager_contract_configuration {
          key
          value
        }
        manager_contract_definition
        manager_current_status
        manager_requested_status
        manager_contract_image
        manager_connector_logs
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
                authorized_authorities
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
