import { ReactNode } from 'react';
import { CheckCircleOutlined, DeleteOutlined, ExtensionOutlined, RefreshOutlined, WarningOutlined, DoNotDisturb, DataSaverOn, OpenWithOutlined } from '@mui/icons-material';
import List from '@mui/material/List';
import { Divider, Stack } from '@mui/material';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { useTheme } from '@mui/material/styles';
import { graphql } from 'react-relay';
import { Spinner, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import IconButton from '@common/button/IconButton';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import Security from '../../../../utils/Security';
import DisabledReasonTooltip from '@common/tooltip/DisabledReasonTooltip';
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

interface ReviewActionProps {
  label: string;
  icon: ReactNode;
  disabled?: boolean;
  disabledReason?: string;
  onClick: () => void;
}

/**
 * A review action of a work. Disabled with a reason, it stays in the keyboard path and says why.
 */
const ReviewAction = ({ label, icon, disabled = false, disabledReason, onClick }: ReviewActionProps) => {
  if (disabledReason) {
    return (
      <DisabledReasonTooltip reason={disabledReason} label={label}>
        <IconButton disabled aria-label={label}>{icon}</IconButton>
      </DisabledReasonTooltip>
    );
  }
  return (
    <IconButton disabled={disabled} tooltip={label} aria-label={label} onClick={onClick}>
      {icon}
    </IconButton>
  );
};

interface ConnectorWorkListProps {
  items: ReadonlyArray<ConnectorWorkListItem>;
  onRefresh: (connector: ConnectorWorkListConnector) => void;
  canRefresh?: boolean;
  onWorkDeleted?: () => void;
  onReviewDismiss?: (workId: string) => void;
  onReview?: (workId: string) => void;
  onReviewAddAll?: (workId: string) => void;
  canEditInvestigation?: boolean;
  /** Why the results cannot be reviewed, which disables the review actions and says so in their tooltip. */
  reviewDisabledReason?: string;
}

/**
 * Lists connectors with their works: each connector can be run again, and each work shows its status and messages.
 */
const ConnectorWorkList = ({
  items,
  onRefresh,
  canRefresh = true,
  onWorkDeleted,
  onReviewDismiss,
  onReview,
  onReviewAddAll,
  canEditInvestigation = false,
  reviewDisabledReason,
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
              secondaryAction={canRefresh && (
                <Security needs={[KNOWLEDGE_KNENRICHMENT]}>
                  <Stack>
                    <IconButton
                      disabled={!connector.active || isRefreshing}
                      onClick={() => onRefresh(connector)}
                      tooltip={t_i18n('Refresh the knowledge using this connector')}
                      aria-label={t_i18n('Refresh the knowledge using this connector')}
                    >
                      <RefreshOutlined />
                    </IconButton>
                  </Stack>
                </Security>
              )}
            >
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
                  <ListItem
                    key={work.id}
                    dense
                    divider
                    secondaryAction={(
                      <Security needs={['CONNECTORAPI', 'MODULES_MODMANAGE']}>
                        <Stack
                          direction="row"
                          spacing={1}
                        >
                          {onReview && (
                            <ReviewAction
                              label={t_i18n('Review results')}
                              icon={<OpenWithOutlined fontSize="small" />}
                              disabled={isFail}
                              disabledReason={reviewDisabledReason}
                              onClick={() => onReview(work.id)}
                            />
                          )}
                          {canEditInvestigation && onReviewAddAll && (
                            <ReviewAction
                              label={t_i18n('Add all to graph')}
                              icon={<DataSaverOn fontSize="small" />}
                              disabled={isFail}
                              disabledReason={reviewDisabledReason}
                              onClick={() => onReviewAddAll(work.id)}
                            />
                          )}
                          {canEditInvestigation && onReviewDismiss && (
                            <ReviewAction
                              label={t_i18n('Mark as reviewed')}
                              icon={<DoNotDisturb fontSize="small" />}
                              disabledReason={reviewDisabledReason}
                              onClick={() => onReviewDismiss(work.id)}
                            />
                          )}
                          {(onReview || onReviewAddAll || onReviewDismiss) && (
                            <Divider orientation="vertical" flexItem />
                          )}
                          <IconButton
                            tooltip={t_i18n('Delete')}
                            aria-label={t_i18n('Delete')}
                            onClick={() => deleteWork(work.id)}
                          >
                            <DeleteOutlined />
                          </IconButton>
                        </Stack>
                      </Security>
                    )}
                  >
                    {/* The messages of the work show on its status and date, apart from the tooltips of its actions. */}
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <div style={{ display: 'flex', alignItems: 'center', flex: 1, minWidth: 0 }}>
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
                        </div>
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
                  </ListItem>
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
