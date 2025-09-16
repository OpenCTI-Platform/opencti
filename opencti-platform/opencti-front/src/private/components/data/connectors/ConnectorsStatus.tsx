import React, { FunctionComponent, useEffect, useMemo, useState } from 'react';
import { interval } from 'rxjs';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import { graphql, PreloadedQuery, useQueryLoader } from 'react-relay';
import { DeleteOutlined, DeveloperBoardOutlined, ExtensionOutlined, HubOutlined, PlaylistRemoveOutlined } from '@mui/icons-material';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import List from '@mui/material/List';
import Tooltip from '@mui/material/Tooltip';
import IconButton from '@mui/material/IconButton';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { ConnectorsStatusQuery } from '@components/data/connectors/__generated__/ConnectorsStatusQuery.graphql';
import { ConnectorsStatus_data$key } from '@components/data/connectors/__generated__/ConnectorsStatus_data.graphql';
import makeStyles from '@mui/styles/makeStyles';
import DialogTitle from '@mui/material/DialogTitle';
import { ListItemButton, Stack } from '@mui/material';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import { useTheme } from '@mui/styles';
import useConnectorsStatusFilters from '@components/data/connectors/hooks/useConnectorsStatusFilters';
import ConnectorsStatusFilters from '@components/data/connectors/ConnectorsStatusFilters';
import ConnectorStatusChip from '@components/data/connectors/ConnectorStatusChip';
import { ManagerContractDefinition, managerContractDefinitionSchema } from '@components/data/connectors/utils/managerContractDefinitionType';
import Transition from '../../../../components/Transition';
import { FIVE_SECONDS } from '../../../../utils/Time';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation, MESSAGING$ } from '../../../../relay/environment';
import Security from '../../../../utils/Security';
import { MODULES_MODMANAGE } from '../../../../utils/hooks/useGranted';
import { type Connector, getConnectorTriggerStatus } from '../../../../utils/Connector';
import { connectorDeletionMutation, connectorResetStateMutation } from './Connector';
import ItemBoolean from '../../../../components/ItemBoolean';
import type { Theme } from '../../../../components/Theme';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import usePreloadedFragment from '../../../../utils/hooks/usePreloadedFragment';
import SortConnectorsHeader from './SortConnectorsHeader';
import useSensitiveModifications from '../../../../utils/hooks/useSensitiveModifications';
import useHelper from '../../../../utils/hooks/useHelper';

const interval$ = interval(FIVE_SECONDS);

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>({
  linesContainer: {
    marginTop: 10,
  },
  itemHead: {
    paddingLeft: 10,
    textTransform: 'uppercase',
    cursor: 'pointer',
  },
  item: {
    paddingLeft: 10,
    height: 50,
  },
  bodyItem: {
    height: 20,
    fontSize: 13,
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
});

export const connectorsStatusQuery = graphql`
  query ConnectorsStatusQuery($enableComposerFeatureFlag: Boolean!) {
    ...ConnectorsStatus_data
  }
`;

const connectorsStatusFragment = graphql`
  fragment ConnectorsStatus_data on Query {
    connectorManagers @include(if: $enableComposerFeatureFlag) {
      id
      name
      active
      last_sync_execution
    }
    catalogs @include(if: $enableComposerFeatureFlag) {
      id
      name
      description
      contracts
    }
    connectors {
      id
      name
      active
      auto
      connector_trigger_filters
      connector_type
      connector_scope
      is_managed @include(if: $enableComposerFeatureFlag)
      manager_current_status @include(if: $enableComposerFeatureFlag)
      manager_requested_status @include(if: $enableComposerFeatureFlag)
      manager_contract_image @include(if: $enableComposerFeatureFlag)
      manager_contract_definition  @include(if: $enableComposerFeatureFlag)
      manager_contract_configuration  @include(if: $enableComposerFeatureFlag) {
        key
        value
      }
      connector_user {
        id
        name
      }
      updated_at
      config {
        listen
        listen_exchange
        push
        push_exchange
      }
      built_in
    }
    rabbitMQMetrics {
      queues {
        name
        messages
        messages_ready
        messages_unacknowledged
        consumers
        idle_since
        message_stats {
          ack
          ack_details {
            rate
          }
        }
      }
    }
  }
`;

interface ConnectorsStatusComponentProps {
  queryRef: PreloadedQuery<ConnectorsStatusQuery>;
  refetch: () => void;
}

const ConnectorsStatusComponent: FunctionComponent<ConnectorsStatusComponentProps> = ({
  queryRef,
  refetch,
}) => {
  const { t_i18n, nsdt, n } = useFormatter();

  const { isFeatureEnable } = useHelper();
  const isComposerEnable = isFeatureEnable('COMPOSER');

  const classes = useStyles(); // TODO remove as deprecated
  const theme = useTheme<Theme>();
  const navigate = useNavigate();
  const { isSensitive } = useSensitiveModifications('connector_reset');

  const [sortBy, setSortBy] = useState<string>('name');
  const [orderAsc, setOrderAsc] = useState<boolean>(true);
  const [connectorIdToReset, setConnectorIdToReset] = useState<string>();
  const [connectorMessages, setConnectorMessages] = useState<string | number | null | undefined>();
  const [resetting, setResetting] = useState<boolean>(false);

  const data = usePreloadedFragment<ConnectorsStatusQuery,
  ConnectorsStatus_data$key>({
    queryDef: connectorsStatusQuery,
    fragmentDef: connectorsStatusFragment,
    queryRef,
  });

  useEffect(() => {
    // Refresh
    const subscription = interval$.subscribe(() => {
      refetch();
    });
    return function cleanup() {
      subscription.unsubscribe();
    };
  }, []);

  const [searchParams] = useSearchParams();

  const managerContractDefinitionMap = useMemo(() => {
    const definitionMap = new Map<string, ManagerContractDefinition>();

    data.connectors.forEach((c) => {
      const parsedDefinition = typeof c.manager_contract_definition === 'string'
        ? JSON.parse(c.manager_contract_definition)
        : c.manager_contract_definition;

      if (parsedDefinition) {
        try {
          const validated = managerContractDefinitionSchema.validateSync(parsedDefinition);
          definitionMap.set(c.id, validated);
        } catch (error) {
          MESSAGING$.notifyError(t_i18n('Failed to parse a connector manager contract definition'));
        }
      }
    });

    return definitionMap;
  }, [data.connectors]);

  const { filteredConnectors, filters, setFilters } = useConnectorsStatusFilters({
    connectors: data.connectors,
    managerContractDefinitionMap,
    searchParams,
  });

  const managedConnectorOptions = useMemo(() => {
    if (!data.connectors) return [];

    const uniqueContracts = new Map();

    data.connectors.forEach((connector) => {
      const definition = managerContractDefinitionMap.get(connector.id);
      if (definition) {
        uniqueContracts.set(definition.slug, definition.title);
      }
    });

    return Array.from(uniqueContracts.entries()).map(([slug, title]) => ({
      label: title,
      value: slug,
    }));
  }, [data.connectors, managerContractDefinitionMap]);

  // eslint-disable-next-line class-methods-use-this
  const submitResetState = (connectorId: string | undefined) => {
    if (connectorId === undefined) return;
    setResetting(true);
    commitMutation({
      mutation: connectorResetStateMutation,
      variables: {
        id: connectorId,
      },
      onCompleted: () => {
        MESSAGING$.notifySuccess('The connector state has been reset');
        setResetting(false);
        setConnectorIdToReset(undefined);
      },
      updater: undefined,
      optimisticResponse: undefined,
      optimisticUpdater: undefined,
      onError: undefined,
      setSubmitting: undefined,
    });
  };

  const handleDelete = (connectorId: string) => {
    commitMutation({
      mutation: connectorDeletionMutation,
      variables: {
        id: connectorId,
      },
      onCompleted: () => {
        MESSAGING$.notifySuccess('The connector has been cleared');
        navigate('/dashboard/data/ingestion/connectors');
      },
      updater: undefined,
      optimisticResponse: undefined,
      optimisticUpdater: undefined,
      onError: undefined,
      setSubmitting: undefined,
    });
  };

  const reverseBy = (field: string) => {
    setSortBy(field);
    setOrderAsc(!orderAsc);
  };

  const queues = data.rabbitMQMetrics?.queues ?? [];

  const connectorsWithMessages = filteredConnectors?.map((connector) => {
    const queueName = connector.connector_type === 'INTERNAL_ENRICHMENT'
      ? `listen_${connector.id}`
      : `push_${connector.id}`;
    const queue = queues.find((o) => o?.name?.includes(queueName));
    const messagesCount = queue ? queue.messages : 0;
    const connectorTriggerStatus = getConnectorTriggerStatus(connector as unknown as Connector);
    return {
      ...connector,
      messages: messagesCount,
      connectorTriggerStatus,
    };
  }) || [];

  const sortedConnectors = connectorsWithMessages.sort((a, b) => {
    let valueA = a[sortBy as keyof typeof connectorsWithMessages[number]];
    let valueB = b[sortBy as keyof typeof connectorsWithMessages[number]];
    // messages are number in string, we shall parse before sorting
    if (sortBy === 'messages') {
      valueA = Number.parseInt(valueA, 10);
      valueB = Number.parseInt(valueB, 10);
    }
    // auto is a boolean but in the UI there are 3 values possibly displayed
    if (sortBy === 'auto') {
      if (a.connector_type === 'INTERNAL_ENRICHMENT' || a.connector_type === 'INTERNAL_IMPORT_FILE') {
        valueA = valueA ? 1 : 0; // 'manual' or 'automatic'
      } else {
        valueA = -1; // 'not applicable'
      }
      if (b.connector_type === 'INTERNAL_ENRICHMENT' || b.connector_type === 'INTERNAL_IMPORT_FILE') {
        valueB = valueB ? 1 : 0;
      } else {
        valueB = -1;
      }
    }
    // is_managed is a boolean, convert to number for sorting
    if (sortBy === 'is_managed') {
      valueA = valueA ? 1 : 0;
      valueB = valueB ? 1 : 0;
    }
    if (orderAsc) {
      return valueA < valueB ? -1 : 1;
    }
    return valueA > valueB ? -1 : 1;
  });

  const gridColumns = isComposerEnable
    ? '20% 10% 15% 10% 15% 15% 15%'
    : '24% 12% 18% 12% 17% 17%';

  return (
    <>
      <Dialog
        slotProps={{ paper: { elevation: 1 } }}
        open={!!connectorIdToReset}
        keepMounted={true}
        slots={{ transition: Transition }}
        onClose={() => setConnectorIdToReset(undefined)}
      >
        <DialogTitle>
          {t_i18n('Are you sure?')}
        </DialogTitle>
        <DialogContent>
          <DialogContentText>
            {t_i18n('Do you want to reset the state and purge messages queue of this connector?')}
          </DialogContentText>
          <DialogContentText>
            {t_i18n('Number of messages: ') + connectorMessages}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button
            onClick={() => setConnectorIdToReset(undefined)}
            disabled={resetting}
          >
            {t_i18n('Cancel')}
          </Button>
          <Button
            onClick={() => {
              submitResetState(connectorIdToReset);
            }}
            color="secondary"
            disabled={resetting}
          >
            {t_i18n('Confirm')}
          </Button>
        </DialogActions>
      </Dialog>

      <Stack gap={1}>
        <Typography variant="h4">{t_i18n('Registered connectors')}</Typography>

        <ConnectorsStatusFilters
          managedConnectorOptions={managedConnectorOptions}
          filters={filters}
          onFiltersChange={setFilters}
        />

        <div className="clearfix" />
        <Paper
          className={'paper-for-grid'}
          style={{
            padding: `${theme.spacing(1)} ${theme.spacing(2)}`,
          }}
          variant="outlined"
        >
          <List classes={{ root: classes.linesContainer }}>
            <ListItem
              classes={{ root: classes.itemHead }}
              divider={false}
              style={{ paddingTop: 0 }}
              secondaryAction={<> &nbsp; </>}
            >
              <ListItemIcon>
                <span
                  style={{
                    padding: '0 8px 0 8px',
                    fontWeight: 700,
                    fontSize: 12,
                  }}
                />
              </ListItemIcon>
              <ListItemText
                primary={
                  <div style={{
                    display: 'grid',
                    gridTemplateColumns: gridColumns,
                  }}
                  >
                    <SortConnectorsHeader field="name" label="Name" isSortable orderAsc={orderAsc} sortBy={sortBy} reverseBy={reverseBy} />
                    <SortConnectorsHeader field="connector_type" label="Type" isSortable orderAsc={orderAsc} sortBy={sortBy} reverseBy={reverseBy} />
                    <SortConnectorsHeader field="auto" label="Automatic trigger" isSortable orderAsc={orderAsc} sortBy={sortBy} reverseBy={reverseBy} />
                    <SortConnectorsHeader field="messages" label="Messages" isSortable orderAsc={orderAsc} sortBy={sortBy} reverseBy={reverseBy} />
                    <SortConnectorsHeader field="active" label="Status" isSortable orderAsc={orderAsc} sortBy={sortBy} reverseBy={reverseBy} />
                    <SortConnectorsHeader field="updated_at" label="Modified" isSortable orderAsc={orderAsc} sortBy={sortBy} reverseBy={reverseBy} />
                    {
                      isComposerEnable && (
                        <SortConnectorsHeader field="is_managed" label={t_i18n('Manager deployment')} isSortable orderAsc={orderAsc} sortBy={sortBy} reverseBy={reverseBy} />
                      )
                    }
                  </div>
                }
              />
            </ListItem>

            <div>
              {sortedConnectors && sortedConnectors
                .filter((connector) => connector.connector_type !== 'internal')
                .map((connector) => {
                  let ConnectorIcon = ExtensionOutlined;
                  if (connector.is_managed) {
                    ConnectorIcon = HubOutlined;
                  } else if (connector.built_in) {
                    ConnectorIcon = DeveloperBoardOutlined;
                  }
                  return (
                    <ListItem
                      key={connector.id}
                      divider={true}
                      disablePadding
                      secondaryAction={
                        <Security needs={[MODULES_MODMANAGE]}>
                          <>
                            {!isSensitive && (
                            <Tooltip title={t_i18n('Reset the connector state')}>
                              <span>
                                <IconButton
                                  onClick={() => {
                                    setConnectorIdToReset(connector.id);
                                    setConnectorMessages(connector.messages);
                                  }}
                                  aria-haspopup="true"
                                  color="primary"
                                  size="large"
                                  disabled={!!connector.built_in}
                                >
                                  <PlaylistRemoveOutlined />
                                </IconButton>
                              </span>
                            </Tooltip>
                            )}
                            <Tooltip title={t_i18n('Clear this connector')} >
                              <span>
                                <IconButton
                                  onClick={() => {
                                    if (connector.id) handleDelete(connector.id);
                                  }}
                                  aria-haspopup="true"
                                  color="primary"
                                  disabled={!!connector.active || !!connector.built_in}
                                  size="large"
                                >
                                  <DeleteOutlined />
                                </IconButton>
                              </span>
                            </Tooltip>
                          </>
                        </Security>
                            }
                    >
                      <ListItemButton
                        component={Link}
                        classes={{ root: classes.item }}
                        to={`/dashboard/data/ingestion/connectors/${connector.id}`}
                      >
                        <ListItemIcon>
                          <ConnectorIcon />
                        </ListItemIcon>

                        <ListItemText
                          primary={
                            <div
                              style={{
                                display: 'grid',
                                gridTemplateColumns: gridColumns,
                              }}
                            >
                              <div className={classes.bodyItem}>
                                {connector.name}
                              </div>
                              <div className={classes.bodyItem}>
                                {t_i18n(connector.connector_type)}
                              </div>
                              <div className={classes.bodyItem}>
                                <ItemBoolean
                                  label={connector.connectorTriggerStatus.label}
                                  status={connector.connectorTriggerStatus.status}
                                  variant="inList"
                                />
                              </div>
                              <div className={classes.bodyItem}>
                                {n(connector.messages)}
                              </div>
                              <div className={classes.bodyItem}>
                                <ConnectorStatusChip connector={connector} />
                              </div>
                              <div className={classes.bodyItem}>
                                {nsdt(connector.updated_at)}
                              </div>
                              {
                                isComposerEnable && (
                                  <div className={classes.bodyItem}>
                                    <ItemBoolean
                                      label={connector.is_managed ? 'TRUE' : 'FALSE'}
                                      status={connector.is_managed}
                                      variant="inList"
                                    />
                                  </div>
                                )
                              }
                            </div>
                          }
                        />
                      </ListItemButton>
                    </ListItem>
                  );
                })}
            </div>
          </List>
        </Paper>
      </Stack>
    </>
  );
};

const ConnectorsStatus = () => {
  const { isFeatureEnable } = useHelper();
  const enableComposerFeatureFlag = isFeatureEnable('COMPOSER');
  const [queryRef, loadQuery] = useQueryLoader<ConnectorsStatusQuery>(connectorsStatusQuery);
  useEffect(() => {
    loadQuery({ enableComposerFeatureFlag }, { fetchPolicy: 'store-and-network' });
  }, []);

  const refetch = React.useCallback(() => {
    loadQuery({ enableComposerFeatureFlag }, { fetchPolicy: 'store-and-network' });
  }, [queryRef]);

  return (
    <>
      {queryRef ? (
        <React.Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <ConnectorsStatusComponent
            queryRef={queryRef}
            refetch={refetch}
          />
        </React.Suspense>
      ) : (
        <Loader variant={LoaderVariant.container} />
      )}
    </>
  );
};

export default ConnectorsStatus;
