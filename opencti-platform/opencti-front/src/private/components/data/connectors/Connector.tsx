import React, { FunctionComponent, useCallback, useEffect, useState } from 'react';
import { createRefetchContainer, graphql, RelayRefetchProp } from 'react-relay';
import Grid from '@mui/material/Grid';
import Typography from '@mui/material/Typography';
import Box from '@mui/material/Box';
import Button from '@common/button/Button';
import { interval } from 'rxjs';
import Tooltip from '@mui/material/Tooltip';
import { InformationOutline } from 'mdi-material-ui';
import { useTheme } from '@mui/styles';
import { Link } from 'react-router-dom';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import { ListItemButton, Stack } from '@mui/material';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Alert from '@mui/material/Alert';
import UpdateIcon from '@mui/icons-material/Update';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import ConnectorPopover from '@components/data/connectors/ConnectorPopover';
import ConnectorStatusChip from '@components/data/connectors/ConnectorStatusChip';
import Filters from '../../common/lists/Filters';
import ItemBoolean from '../../../../components/ItemBoolean';
import { useFormatter } from '../../../../components/i18n';
import {
  useGetConnectorAvailableFilterKeys,
  useGetConnectorFilterEntityTypes,
  getConnectorOnlyContextualStatus,
  getConnectorTriggerStatus,
  computeConnectorStatus,
} from '../../../../utils/Connector';
import { deserializeFilterGroupForFrontend, isFilterGroupNotEmpty, serializeFilterGroupForBackend } from '../../../../utils/filters/filtersUtils';
import useFiltersState from '../../../../utils/filters/useFiltersState';
import { FIVE_SECONDS, formatUptime } from '../../../../utils/Time';
import Security from '../../../../utils/Security';
import useGranted, { MODULES_MODMANAGE, SETTINGS_SETACCESSES } from '../../../../utils/hooks/useGranted';
import { MESSAGING$, QueryRenderer } from '../../../../relay/environment';
import ConnectorWorks, { connectorWorksQuery } from './ConnectorWorks';
import FilterIconButton from '../../../../components/FilterIconButton';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import ItemCopy from '../../../../components/ItemCopy';
import ItemIcon from '../../../../components/ItemIcon';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import type { Theme } from '../../../../components/Theme';
import { Connector_connector$data } from './__generated__/Connector_connector.graphql';
import { ConnectorUpdateTriggerMutation, EditInput } from './__generated__/ConnectorUpdateTriggerMutation.graphql';
import { ConnectorUpdateStatusMutation } from './__generated__/ConnectorUpdateStatusMutation.graphql';
import { ConnectorWorksQuery$data, ConnectorWorksQuery$variables } from './__generated__/ConnectorWorksQuery.graphql';
import Card from '../../../../components/common/card/Card';
import TitleMainEntity from '../../../../components/common/typography/TitleMainEntity';
import Label from '../../../../components/common/label/Label';
import Tag from '../../../../components/common/tag/Tag';

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

// Component for ConnectorWorks sections
interface ConnectorWorksSectionProps {
  connectorId: string;
}

const ConnectorWorksSection: FunctionComponent<ConnectorWorksSectionProps> = ({ connectorId }) => {
  const optionsInProgress: ConnectorWorksQuery$variables = {
    count: 50,
    orderMode: 'asc',
    filters: {
      mode: 'and',
      filters: [
        { key: ['connector_id'], values: [connectorId] },
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
        { key: ['connector_id'], values: [connectorId] },
        { key: ['status'], values: ['complete'] },
      ],
      filterGroups: [],
    },
  };

  return (
    <Stack spacing={3}>
      <QueryRenderer
        key="connector-works-in-progress"
        query={connectorWorksQuery}
        variables={optionsInProgress}
        fetchPolicy="cache-and-network"
        render={({ props }: { props: ConnectorWorksQuery$data | null }) => {
          if (props) {
            return <ConnectorWorks data={props} options={[optionsInProgress]} inProgress={true} />;
          }
          return <Loader variant={LoaderVariant.inElement} />;
        }}
      />

      <QueryRenderer
        key="connector-works-finished"
        query={connectorWorksQuery}
        variables={optionsFinished}
        fetchPolicy="cache-and-network"
        render={({ props }: { props: ConnectorWorksQuery$data | null }) => {
          if (props) {
            return <ConnectorWorks data={props} options={[optionsFinished]} />;
          }
          return <Loader variant={LoaderVariant.inElement} />;
        }}
      />
    </Stack>
  );
};

ConnectorWorksSection.displayName = 'ConnectorWorksSection';

interface ConnectorComponentProps {
  connector: Connector_connector$data;
  relay: RelayRefetchProp;
}

const ConnectorComponent: FunctionComponent<ConnectorComponentProps> = ({ connector, relay }) => {
  const { t_i18n, nsdt } = useFormatter();
  const theme = useTheme<Theme>();

  const handleRefreshData = useCallback(() => {
    // Need to force refetch with network-only to bypass cache
    // to prevent merging data when create/edit connector and fetch connector data
    relay.refetch(
      { id: connector.id },
      null,
      null,
      { force: true },
    );
  }, [connector.id, relay]);

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
  const [tabValue, setTabValue] = useState(0);

  // API mutations - defined early to avoid use-before-define errors
  const [commitUpdateStatus] = useApiMutation<ConnectorUpdateStatusMutation>(updateRequestedStatus);
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

  const filtersSearchContext = { entityTypes: connectorFiltersScope, connectorsScope: true };

  const userHasSettingsCapability = useGranted([SETTINGS_SETACCESSES]);
  const connectorStateConverted = connector.connector_state ? JSON.parse(connector.connector_state) : null;
  const checkLastRunExistingInState = connectorStateConverted && Object.prototype.hasOwnProperty.call(connectorStateConverted, 'last_run');
  const checkLastRunIsNumber = checkLastRunExistingInState && Number.isFinite(connectorStateConverted.last_run);
  const lastRunConverted = checkLastRunIsNumber && new Date(connectorStateConverted.last_run * 1000);

  const isBuffering = () => {
    return connector.connector_info ? connector.connector_info.queue_messages_size > connector.connector_info.queue_threshold : false;
  };

  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
  };

  // Component for Overview content (without ConnectorWorks)
  const ConnectorOverview = () => (
    <>
      <Grid container={true} spacing={3} style={{ marginBottom: 20 }}>
        <Grid item xs={6}>
          <Card title={t_i18n('Basic information')}>
            <Grid container={true} spacing={2}>
              <Grid item xs={6}>
                <Label>
                  {t_i18n('Type')}
                </Label>
                <Tag
                  key={connector.connector_type}
                  label={connector.connector_type ?? ''}
                />
              </Grid>
              <Grid item xs={6}>
                <Label>
                  {t_i18n('Last update')}
                </Label>
                {nsdt(connector.updated_at)}
              </Grid>
              <Grid item xs={6}>
                <Label>
                  {t_i18n('Only contextual')}
                </Label>
                <ItemBoolean
                  status={connectorOnlyContextualStatus.status}
                  label={connectorOnlyContextualStatus.label}
                />
              </Grid>
              <Grid item xs={6}>
                <Label>
                  {t_i18n('Automatic trigger')}
                </Label>
                <ItemBoolean
                  status={connectorTriggerStatus.status}
                  label={connectorTriggerStatus.label}
                />
              </Grid>
              <Grid item xs={connectorFiltersEnabled ? 6 : 12}>
                <Label>
                  {t_i18n('Scope')}
                </Label>
                {connector.connector_scope?.map((scope) => (
                  <Tag
                    key={scope}
                    label={scope}
                    sx={{ mr: 1 }}
                  />
                ))}
              </Grid>
              {connectorFiltersEnabled && (
                <Grid item xs={6}>
                  <Label action={(
                    <Tooltip
                      title={t_i18n('Trigger filters can be used to trigger automatically this connector on entities matching the filters and scope.')}
                    >
                      <InformationOutline fontSize="small" color="primary" />
                    </Tooltip>
                  )}
                  >
                    {t_i18n('Trigger filters')}
                  </Label>
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
                    <Label>
                      {t_i18n('Associated user')}
                    </Label>
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
                    <Label>
                      {t_i18n('Max confidence level')}
                    </Label>
                    {connector.connector_user ? (
                      <FieldOrEmpty source={connector.connector_user?.effective_confidence_level?.max_confidence}>
                        {connector.connector_user.effective_confidence_level?.max_confidence}
                      </FieldOrEmpty>
                    ) : (
                      <FieldOrEmpty source={connector.connector_user}>{null}</FieldOrEmpty>
                    )}
                  </Grid>
                  <Grid item xs={6}>
                    <Label>
                      {t_i18n("User's roles")}
                    </Label>
                    {connector.connector_user ? (
                      <FieldOrEmpty source={connector.connector_user.roles ?? []}>
                        <List sx={{ py: 0 }}>
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
                    <Label>
                      {t_i18n("User's groups")}
                    </Label>
                    {connector.connector_user ? (
                      <FieldOrEmpty source={connector.connector_user.groups?.edges}>
                        <List sx={{ py: 0 }}>
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
                    <Label>
                      {t_i18n("User's organizations")}
                    </Label>
                    {connector.connector_user ? (
                      <FieldOrEmpty source={connector.connector_user.objectOrganization?.edges}>
                        <List sx={{ py: 0 }}>
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
                                      ? theme.palette.dangerZone.main
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
          </Card>
        </Grid>
        <Grid item xs={6}>
          <Card title={t_i18n('Details')}>
            <Grid container={true} spacing={2}>
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
                <Label>
                  {t_i18n('State')}
                </Label>
                <FieldOrEmpty source={connector.connector_state}>
                  <pre>
                    <ItemCopy
                      content={connector.connector_state || ''}
                      limit={200}
                    />
                  </pre>
                </FieldOrEmpty>
              </Grid>

              <Grid item xs={6}>
                {!connector.connector_info && (
                  connector.connector_state
                  && connectorStateConverted !== null
                  && checkLastRunExistingInState && checkLastRunIsNumber ? (
                        <>
                          <Label>
                            {t_i18n('Last run (from State)')}
                          </Label>
                          <Typography variant="body1" gutterBottom={true}>
                            {nsdt(lastRunConverted)}
                          </Typography>
                        </>
                      ) : (
                        <>
                          <Label>
                            {t_i18n('Last run')}
                          </Label>
                          <Typography variant="body1" gutterBottom={true}>
                            {t_i18n('Not provided')}
                          </Typography>
                        </>
                      )
                )}
                {connector.connector_info && (
                  connector.connector_info.last_run_datetime ? (
                    <>
                      <Label>
                        {t_i18n('Last run')}
                      </Label>
                      <Typography variant="body1" gutterBottom={true}>
                        {nsdt(connector.connector_info?.last_run_datetime)}
                      </Typography>
                    </>
                  ) : (connector.connector_state
                    && connectorStateConverted !== null
                    && checkLastRunExistingInState && checkLastRunIsNumber ? (
                        <>
                          <Label>
                            {t_i18n('Last run (from State)')}
                          </Label>
                          <Typography variant="body1" gutterBottom={true}>
                            {nsdt(lastRunConverted)}
                          </Typography>
                        </>
                      )
                    : (
                        <>
                          <Label>
                            {t_i18n('Last run')}
                          </Label>
                          <Typography variant="body1" gutterBottom={true}>
                            {t_i18n('Not provided')}
                          </Typography>
                        </>
                      )
                  )
                )}
              </Grid>
              <Grid item xs={6}>
                <Label>
                  {t_i18n('Next run')}
                </Label>
                {connector.connector_info && (
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

              {connector.is_managed && (
                <Grid item xs={6}>
                  <Label>{t_i18n('Instance name')}</Label>
                  <Typography component="div" variant="body1">{connector.name}</Typography>
                </Grid>
              )}

              <Grid item xs={6}>
                <Label>
                  {t_i18n('Server capacity')}
                </Label>
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
              {connector.is_managed && connector.manager_current_status === 'started' && connector.manager_connector_uptime != null && (
                <Grid item xs={6}>
                  <Label>
                    {t_i18n('Uptime')}
                  </Label>
                  <Typography variant="body1" gutterBottom={true}>
                    {formatUptime(connector.manager_connector_uptime, t_i18n)}
                  </Typography>
                </Grid>
              )}
            </Grid>
          </Card>
        </Grid>
      </Grid>
    </>
  );

  // Component for Logs content
  const ConnectorLogs = () => {
    // calculating the full viewport height minus some space for elements above
    const logsContainerHeight = 'calc(100vh - 280px)';
    return (
      <Box sx={{ marginBottom: '20px', height: logsContainerHeight }}>
        <pre
          style={{
            height: '100%',
            overflowX: 'scroll',
            overflowY: 'auto',
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
  };

  return (
    <>
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          width: '100%',
          marginBottom: theme.spacing(3),
        }}
      >
        <TitleMainEntity
          sx={{
            display: 'flex',
            alignItems: 'center',
            gap: theme.spacing(1),
          }}
        >
          {connector.is_managed ? connector.manager_contract_excerpt?.title : connector.name}
          <div style={{ display: 'inline-block' }}>
            <ConnectorStatusChip connector={connector} />
          </div>
        </TitleMainEntity>
        <div style={{
          float: 'right',
          display: 'flex',
          alignItems: 'center',
          gap: theme.spacing(1),
        }}
        >
          <Security needs={[MODULES_MODMANAGE]}>
            <>
              <ConnectorPopover
                connector={connector}
                onRefreshData={handleRefreshData}
              />
              {connector.is_managed && (
                <Button
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
            </>
          </Security>
        </div>
      </div>

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
            {tabValue === 0 && (
              <>
                <ConnectorOverview />
                <ConnectorWorksSection connectorId={connector.id} />
              </>
            )}
            {tabValue === 1 && <ConnectorLogs />}
          </Box>
        </>
      ) : (
        <>
          <ConnectorOverview />
          <ConnectorWorksSection connectorId={connector.id} />
        </>
      )}
    </>
  );
};

export const connectorQuery = graphql`
  query ConnectorQuery($id: String!) {
    connector(id: $id) {
      id
      name
      title
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
        title
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
        manager_contract_excerpt {
            title
        }
        manager_contract_definition
        manager_current_status
        manager_requested_status
        manager_contract_image
        manager_connector_logs
        manager_connector_uptime
        manager_health_metrics {
          restart_count
          started_at
          last_update
          is_in_reboot_loop
        }
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
