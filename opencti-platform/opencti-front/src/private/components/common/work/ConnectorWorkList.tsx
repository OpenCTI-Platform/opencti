import { CheckCircleOutlined, DeleteOutlined, ExtensionOutlined, RefreshOutlined, WarningOutlined } from '@mui/icons-material';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemButton from '@mui/material/ListItemButton';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { useTheme } from '@mui/styles';
import { graphql } from 'react-relay';
import { Spinner, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import IconButton from '@common/button/IconButton';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNENRICHMENT } from '../../../../utils/hooks/useGranted';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { ConnectorWorkListDeleteMutation } from './__generated__/ConnectorWorkListDeleteMutation.graphql';

const connectorWorkListDeleteMutation = graphql`
  mutation ConnectorWorkListDeleteMutation($workId: ID!) {
    workEdit(id: $workId) {
      delete
    }
  }
`;

type ConnectorWorkMessage = {
  readonly timestamp?: string | null;
  readonly message?: string | null;
} | null | undefined;

export interface ConnectorWorkListWork {
  readonly id: string;
  readonly status: string;
  readonly timestamp?: string | null;
  readonly messages?: ReadonlyArray<ConnectorWorkMessage> | null;
  readonly errors?: ReadonlyArray<ConnectorWorkMessage> | null;
}

export interface ConnectorWorkListConnector {
  readonly id: string;
  readonly name: string;
  readonly active?: boolean | null;
  readonly connector_type?: string | null;
}

export interface ConnectorWorkListItem {
  connector: ConnectorWorkListConnector;
  works: ReadonlyArray<ConnectorWorkListWork>;
}

interface ConnectorWorkListProps {
  items: ReadonlyArray<ConnectorWorkListItem>;
  onRefresh: (connector: ConnectorWorkListConnector) => void;
  onWorkDeleted?: () => void;
}

/**
 * Lists connectors with their works: each connector can be run again, and each work shows its status and messages.
 */
const ConnectorWorkList = ({
  items,
  onRefresh,
  onWorkDeleted,
}: ConnectorWorkListProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n, nsdt } = useFormatter();
  const [commitDeleteWork] = useApiMutation<ConnectorWorkListDeleteMutation>(connectorWorkListDeleteMutation);

  /**
   * Deletes the work, then lets the parent refresh its data.
   */
  const deleteWork = (workId: string) => {
    commitDeleteWork({
      variables: { workId },
      onCompleted: () => onWorkDeleted?.(),
    });
  };

  if (items.length === 0) {
    return (
      <List>
        <div style={{ color: theme.palette.text.primary, fontSize: 15 }}>
          {t_i18n('No connectors for this type of entity')}
        </div>
      </List>
    );
  }

  return (
    <List>
      {items.map(({ connector, works }) => {
        const isRefreshing = works.some((work) => work.status !== 'complete');

        return (
          <div key={connector.id}>
            <ListItem
              divider
              disablePadding
              secondaryAction={(
                <Security needs={[KNOWLEDGE_KNENRICHMENT]}>
                  <div style={{ right: 0 }}>
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <span>
                          <IconButton
                            disabled={!connector.active || isRefreshing}
                            onClick={() => onRefresh(connector)}
                            aria-label={t_i18n('Refresh the knowledge using this connector')}
                          >
                            <RefreshOutlined />
                          </IconButton>
                        </span>
                      </TooltipTrigger>
                      <TooltipContent>
                        {t_i18n('Refresh the knowledge using this connector')}
                      </TooltipContent>
                    </Tooltip>
                  </div>
                </Security>
              )}
            >
              <ListItemButton>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <ListItemIcon
                      style={{
                        color: connector.active
                          ? theme.palette.success.main
                          : theme.palette.error.main,
                      }}
                    >
                      <ExtensionOutlined />
                    </ListItemIcon>
                  </TooltipTrigger>
                  <TooltipContent>
                    {connector.active
                      ? t_i18n('This connector is active')
                      : t_i18n('This connector is disconnected')}
                  </TooltipContent>
                </Tooltip>
                <ListItemText primary={connector.name} />
              </ListItemButton>
            </ListItem>

            <List
              component="div"
              disablePadding
            >
              {works.map((work) => {
                const isFail = (work.errors ?? []).length > 0;
                const messages = [...(work.messages ?? []), ...(work.errors ?? [])]
                  .filter((message) => !!message)
                  .sort((a, b) => (a?.timestamp ?? '').localeCompare(b?.timestamp ?? ''));

                return (
                  <Tooltip key={work.id}>
                    <TooltipTrigger asChild>
                      <ListItem
                        dense
                        divider
                        disablePadding
                        secondaryAction={(
                          <Security needs={[KNOWLEDGE_KNENRICHMENT]}>
                            <div style={{ right: 0 }}>
                              <IconButton
                                aria-label={t_i18n('Delete')}
                                onClick={() => deleteWork(work.id)}
                              >
                                <DeleteOutlined />
                              </IconButton>
                            </div>
                          </Security>
                        )}
                      >
                        <ListItemButton sx={{ paddingLeft: theme.spacing(4) }}>
                          <ListItemIcon>
                            {isFail && (
                              <WarningOutlined
                                style={{
                                  fontSize: 15,
                                  color: theme.palette.error.main,
                                }}
                              />
                            )}
                            {!isFail && work.status === 'complete' && (
                              <CheckCircleOutlined
                                style={{
                                  fontSize: 15,
                                  color: theme.palette.success.main,
                                }}
                              />
                            )}
                            {((!isFail && work.status === 'wait') || work.status === 'progress') && (
                              <Spinner
                                size="md"
                                style={{ marginRight: 10 }}
                              />
                            )}
                          </ListItemIcon>
                          <ListItemText primary={nsdt(work.timestamp)} />
                        </ListItemButton>
                      </ListItem>
                    </TooltipTrigger>
                    <TooltipContent style={{ maxWidth: 600 }}>
                      {messages.length > 0
                        ? messages.map((message, index) => (
                            <div key={`${message?.timestamp}-${index}`}>
                              [{nsdt(message?.timestamp)}] {message?.message}
                            </div>
                          ))
                        : t_i18n(work.status)}
                    </TooltipContent>
                  </Tooltip>
                );
              })}
            </List>
          </div>
        );
      })}
    </List>
  );
};

export default ConnectorWorkList;
