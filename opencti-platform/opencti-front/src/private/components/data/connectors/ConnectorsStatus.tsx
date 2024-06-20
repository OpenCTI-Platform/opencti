import React, { CSSProperties, FunctionComponent, useEffect, useState } from 'react';
import { interval } from 'rxjs';
import Card from '@mui/material/Card';
import CardHeader from '@mui/material/CardHeader';
import CardContent from '@mui/material/CardContent';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import { graphql, PreloadedQuery, useQueryLoader } from 'react-relay';
import { ExtensionOutlined, DeleteOutlined, PlaylistRemoveOutlined } from '@mui/icons-material';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import List from '@mui/material/List';
import Tooltip from '@mui/material/Tooltip';
import IconButton from '@mui/material/IconButton';
import { Link, useNavigate } from 'react-router-dom';
import { ConnectorsStatusQuery } from '@components/data/connectors/__generated__/ConnectorsStatusQuery.graphql';
import { ConnectorsStatus_data$key } from '@components/data/connectors/__generated__/ConnectorsStatus_data.graphql';
import makeStyles from '@mui/styles/makeStyles';
import { ListItemButton } from '@mui/material';
import Transition from '../../../../components/Transition';
import { FIVE_SECONDS } from '../../../../utils/Time';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation, MESSAGING$ } from '../../../../relay/environment';
import Security from '../../../../utils/Security';
import { MODULES_MODMANAGE } from '../../../../utils/hooks/useGranted';
import { connectorDeletionMutation, connectorResetStateMutation } from './Connector';
import ItemBoolean from '../../../../components/ItemBoolean';
import type { Theme } from '../../../../components/Theme';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import usePreloadedFragment from '../../../../utils/hooks/usePreloadedFragment';
import SortConnectorsHeader from './SortConnectorsHeader';

const interval$ = interval(FIVE_SECONDS);

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
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
    height: '100%',
    fontSize: 13,
  },
  icon: {
    color: theme.palette.primary.main,
  },
}));

const inlineStyles: Record<string, CSSProperties> = {
  name: {
    float: 'left',
    width: '35%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  connector_type: {
    float: 'left',
    width: '20%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  auto: {
    float: 'left',
    width: '20%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  messages: {
    float: 'left',
    width: '10%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  updated_at: {
    float: 'left',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
};

export const connectorsStatusQuery = graphql`
  query ConnectorsStatusQuery {
    ...ConnectorsStatus_data
  }
`;

const connectorsStatusFragment = graphql`
      fragment ConnectorsStatus_data on Query {
        connectors {
          id
          name
          active
          auto
          connector_type
          connector_scope
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
  const classes = useStyles(); // TODO remove as deprecated
  const navigate = useNavigate();
  const [sortBy, setSortBy] = useState<string>('name');
  const [orderAsc, setOrderAsc] = useState<boolean>(true);
  const [connectorIdToReset, setConnectorIdToReset] = useState<string>();
  const [connectorMessages, setConnectorMessages] = useState<string | number | null | undefined>();
  const [resetting, setResetting] = useState<boolean>(false);

  const data = usePreloadedFragment<
  ConnectorsStatusQuery,
  ConnectorsStatus_data$key
  >({
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
  const connectorsWithMessages = data.connectors?.map((connector) => {
    const queueName = connector?.connector_type === 'INTERNAL_ENRICHMENT'
      ? `listen_${connector?.id}`
      : `push_${connector?.id}`;
    const queue = queues.find((o) => o?.name?.includes(queueName));
    const messagesCount = queue ? queue.messages : 0;
    return {
      ...connector,
      messages: messagesCount,
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
    if (orderAsc) {
      return valueA < valueB ? -1 : 1;
    }
    return valueA > valueB ? -1 : 1;
  });

  return (
    <>
      <Dialog
        PaperProps={{ elevation: 1 }}
        open={!!connectorIdToReset}
        keepMounted={true}
        TransitionComponent={Transition}
        onClose={() => setConnectorIdToReset(undefined)}
      >
        <DialogContent>
          <DialogContentText>
            {t_i18n('Do you want to reset the state and purge messages queue of this connector? ')}
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
            {t_i18n('Reset')}
          </Button>
        </DialogActions>
      </Dialog>
      <Card variant="outlined">
        <CardHeader
          avatar={<ExtensionOutlined className={classes.icon} />}
          title={t_i18n('Registered connectors')}
          style={{ paddingBottom: 0 }}
        />
        <CardContent style={{ paddingTop: 0 }}>
          <List classes={{ root: classes.linesContainer }}>
            <ListItem
              classes={{ root: classes.itemHead }}
              divider={false}
              style={{ paddingTop: 0 }}
            >
              <ListItemIcon>
                <span
                  style={{
                    padding: '0 8px 0 8px',
                    fontWeight: 700,
                    fontSize: 12,
                  }}
                >
                  #
                </span>
              </ListItemIcon>
              <ListItemText
                primary={
                  <div>
                    <SortConnectorsHeader field="name" label="Name" isSortable orderAsc={orderAsc} sortBy={sortBy} reverseBy={reverseBy} />
                    <SortConnectorsHeader field="connector_type" label="Type" isSortable orderAsc={orderAsc} sortBy={sortBy} reverseBy={reverseBy} />
                    <SortConnectorsHeader field="auto" label="Automatic trigger" isSortable orderAsc={orderAsc} sortBy={sortBy} reverseBy={reverseBy} />
                    <SortConnectorsHeader field="messages" label="Messages" isSortable orderAsc={orderAsc} sortBy={sortBy} reverseBy={reverseBy} />
                    <SortConnectorsHeader field="updated_at" label="Modified" isSortable orderAsc={orderAsc} sortBy={sortBy} reverseBy={reverseBy} />
                  </div>
                  }
              />
              <ListItemSecondaryAction> &nbsp; </ListItemSecondaryAction>
            </ListItem>

            {sortedConnectors && sortedConnectors.map((connector) => (
              <ListItemButton
                key={connector.id}
                classes={{ root: classes.item }}
                divider={true}
                component={Link}
                to={`/dashboard/data/ingestion/connectors/${connector.id}`}
              >
                <ListItemIcon
                  style={{ color: connector.active ? '#4caf50' : '#f44336' }}
                >
                  <ExtensionOutlined />
                </ListItemIcon>
                <ListItemText
                  primary={
                    <div>
                      <div
                        className={classes.bodyItem}
                        style={inlineStyles.name}
                      >
                        {connector.name}
                      </div>
                      <div
                        className={classes.bodyItem}
                        style={inlineStyles.connector_type}
                      >
                        {t_i18n(connector.connector_type)}
                      </div>
                      <div
                        className={classes.bodyItem}
                        style={inlineStyles.auto}
                      >
                        <ItemBoolean
                          label={connector.auto ? t_i18n('Automatic') : t_i18n('Manual')}
                          status={
                            connector.connector_type
                              === 'INTERNAL_ENRICHMENT'
                            || connector.connector_type === 'INTERNAL_IMPORT_FILE'
                              ? connector.auto
                              : null
                          }
                          variant="inList"
                        />
                      </div>
                      <div
                        className={classes.bodyItem}
                        style={inlineStyles.messages}
                      >
                        {n(connector.messages)}
                      </div>
                      <div
                        className={classes.bodyItem}
                        style={inlineStyles.updated_at}
                      >
                        {nsdt(connector.updated_at)}
                      </div>
                    </div>
                  }
                />
                <ListItemSecondaryAction>
                  <Security needs={[MODULES_MODMANAGE]}>
                    <>
                      <Tooltip title={t_i18n('Reset the connector state')}>
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
                      </Tooltip>
                      <Tooltip title={t_i18n('Clear this connector')}>
                        <IconButton
                          onClick={() => {
                            if (connector.id) handleDelete(connector.id);
                          }}
                          aria-haspopup="true"
                          color="primary"
                          disabled={!!connector.active}
                          size="large"
                        >
                          <DeleteOutlined />
                        </IconButton>
                      </Tooltip>
                    </>
                  </Security>
                </ListItemSecondaryAction>
              </ListItemButton>
            ))}
          </List>
        </CardContent>
      </Card>
    </>
  );
};

const ConnectorsStatus = () => {
  const [queryRef, loadQuery] = useQueryLoader<ConnectorsStatusQuery>(connectorsStatusQuery);
  useEffect(() => {
    loadQuery({}, { fetchPolicy: 'store-and-network' });
  }, []);

  const refetch = React.useCallback(() => {
    loadQuery({}, { fetchPolicy: 'store-and-network' });
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
