import React, { FunctionComponent, useCallback, useEffect, useMemo, useState } from 'react';
import { interval } from 'rxjs';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import Button from '@common/button/Button';
import { useQueryLoader } from 'react-relay';
import { DeleteOutlined, DeveloperBoardOutlined, ExtensionOutlined, HubOutlined, PlaylistRemoveOutlined } from '@mui/icons-material';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import List from '@mui/material/List';
import Tooltip from '@mui/material/Tooltip';
import IconButton from '@common/button/IconButton';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import makeStyles from '@mui/styles/makeStyles';
import DialogTitle from '@mui/material/DialogTitle';
import { ListItemButton, Stack } from '@mui/material';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import { useTheme } from '@mui/styles';
import useConnectorsStatusFilters from '@components/data/connectors/hooks/useConnectorsStatusFilters';
import ConnectorsStatusFilters from '@components/data/connectors/ConnectorsStatusFilters';
import ConnectorStatusChip from '@components/data/connectors/ConnectorStatusChip';
import ConnectorsList, { connectorsListQuery } from '@components/data/connectors/ConnectorsList';
import ConnectorsState, { connectorsStateQuery } from '@components/data/connectors/ConnectorsState';
import { ConnectorsListQuery } from '@components/data/connectors/__generated__/ConnectorsListQuery.graphql';
import { ConnectorsStateQuery } from '@components/data/connectors/__generated__/ConnectorsStateQuery.graphql';
import { Connector_connector$data } from '@components/data/connectors/__generated__/Connector_connector.graphql';
import { getConnectorMetadata, IngestionConnectorType } from '@components/data/IngestionCatalog/utils/ingestionConnectorTypeMetadata';
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
import SortConnectorsHeader from './SortConnectorsHeader';
import useSensitiveModifications from '../../../../utils/hooks/useSensitiveModifications';
import canDeleteConnector from './utils/canDeleteConnector';

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

interface ConnectorsStatusContentProps {
  connectorsListData: ConnectorsListQuery['response'];
  connectorsStateData: ConnectorsStateQuery['response'];
}

const ConnectorsStatusContent: FunctionComponent<ConnectorsStatusContentProps> = ({
  connectorsListData,
  connectorsStateData,
}) => {
  const { t_i18n, nsdt, n } = useFormatter();

  const classes = useStyles(); // TODO remove as deprecated
  const theme = useTheme<Theme>();
  const { isSensitive } = useSensitiveModifications('connector_reset');

  const navigate = useNavigate();

  const [sortBy, setSortBy] = useState<string>('name');
  const [orderAsc, setOrderAsc] = useState<boolean>(true);
  const [connectorIdToReset, setConnectorIdToReset] = useState<string>();
  const [connectorMessages, setConnectorMessages] = useState<string | number | null | undefined>();
  const [resetting, setResetting] = useState<boolean>(false);

  const connectors = useMemo(() => {
    if (!connectorsListData?.connectors || !connectorsStateData?.connectors) return [];

    return connectorsListData.connectors.map((connector) => {
      const stateConnector = connectorsStateData.connectors.find((s) => s.id === connector.id);
      return {
        ...connector,
        ...stateConnector,
      };
    });
  }, [connectorsListData.connectors, connectorsStateData.connectors]);

  const [searchParams] = useSearchParams();

  const { filteredConnectors, filters, setFilters } = useConnectorsStatusFilters({
    connectors,
    searchParams,
  });

  const managedConnectorOptions = useMemo(() => {
    if (!connectors) return [];

    const uniqueContracts = new Map();

    connectors.forEach((connector) => {
      if (connector.manager_contract_excerpt) {
        const { slug, title } = connector.manager_contract_excerpt;
        uniqueContracts.set(slug, title);
      }
    });

    return Array.from(uniqueContracts, ([slug, title]) => ({
      label: title,
      value: slug,
    })).sort((a, b) => a.label.localeCompare(b.label));
  }, [connectors]);

  const queues = connectorsStateData.rabbitMQMetrics?.queues ?? [];

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

    // Handle manager_contract_info sorting by title
    if (sortBy === 'manager_contract_excerpt') {
      valueA = a.manager_contract_excerpt?.title || '';
      valueB = b.manager_contract_excerpt?.title || '';
    }

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

  const gridColumns = '20% 10% 15% 10% 15% 15% 15%';

  const hasManagedConnectors = connectors.some((c) => c.is_managed);

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
            variant="secondary"
            onClick={() => setConnectorIdToReset(undefined)}
            disabled={resetting}
          >
            {t_i18n('Cancel')}
          </Button>
          <Button
            onClick={() => {
              submitResetState(connectorIdToReset);
            }}
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
          showManagedFilters={hasManagedConnectors}
        />

        <div className="clearfix" />
        <Paper
          className="paper-for-grid"
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
                primary={(
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
                    <SortConnectorsHeader field="is_managed" label={t_i18n('Manager deployment')} isSortable orderAsc={orderAsc} sortBy={sortBy} reverseBy={reverseBy} />
                  </div>
                )}
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

                  const connectorType = connector.connector_type
                    ? getConnectorMetadata(connector.connector_type as IngestionConnectorType, t_i18n).label
                    : '-';

                  return (
                    <ListItem
                      key={connector.id}
                      divider={true}
                      disablePadding
                      secondaryAction={(
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
                                    disabled={!!connector.built_in}
                                  >
                                    <PlaylistRemoveOutlined />
                                  </IconButton>
                                </span>
                              </Tooltip>
                            )}
                            <Tooltip title={t_i18n('Clear this connector')}>
                              <span>
                                <IconButton
                                  onClick={() => {
                                    if (connector.id) handleDelete(connector.id);
                                  }}
                                  aria-haspopup="true"
                                  color="primary"
                                  disabled={!canDeleteConnector(connector as unknown as Connector_connector$data)}
                                >
                                  <DeleteOutlined />
                                </IconButton>
                              </span>
                            </Tooltip>
                          </>
                        </Security>
                      )}
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
                          primary={(
                            <div
                              style={{
                                display: 'grid',
                                gridTemplateColumns: gridColumns,
                              }}
                            >
                              <Tooltip title={connector.title} placement="top">
                                <div className={classes.bodyItem}>
                                  {
                                    connector.is_managed ? connector.manager_contract_excerpt?.title : connector.name
                                  }
                                </div>
                              </Tooltip>
                              <div className={classes.bodyItem}>
                                {connectorType}
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
                              <div className={classes.bodyItem}>
                                <ItemBoolean
                                  label={connector.is_managed ? 'TRUE' : 'FALSE'}
                                  status={connector.is_managed}
                                  variant="inList"
                                />
                              </div>
                            </div>
                          )}
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

const ConnectorsStatus: React.FC = () => {
  const [connectorsListRef, loadConnectorsList] = useQueryLoader<ConnectorsListQuery>(connectorsListQuery);
  const [connectorsStateRef, loadConnectorsState] = useQueryLoader<ConnectorsStateQuery>(connectorsStateQuery);

  useEffect(() => {
    loadConnectorsList({}, { fetchPolicy: 'store-and-network' });
    loadConnectorsState({}, { fetchPolicy: 'store-and-network' });
  }, []);

  const refetchConnectorsState = useCallback(() => {
    loadConnectorsState({}, { fetchPolicy: 'store-and-network' });
  }, []);

  useEffect(() => {
    const subscription = interval$.subscribe(() => {
      refetchConnectorsState();
    });
    return () => subscription.unsubscribe();
  }, [refetchConnectorsState]);

  if (!connectorsListRef || !connectorsStateRef) {
    return <Loader variant={LoaderVariant.container} />;
  }

  return (
    <React.Suspense fallback={<Loader variant={LoaderVariant.container} />}>
      <ConnectorsList queryRef={connectorsListRef}>
        {({ data: connectorsListData }) => (
          <ConnectorsState queryRef={connectorsStateRef}>
            {({ data: connectorsStateData }) => (
              <ConnectorsStatusContent
                connectorsListData={connectorsListData}
                connectorsStateData={connectorsStateData}
              />
            )}
          </ConnectorsState>
        )}
      </ConnectorsList>
    </React.Suspense>
  );
};

export default ConnectorsStatus;
