import React from 'react';
import { Stack, Tooltip, Typography } from '@mui/material';
import Box from '@mui/material/Box';
import { alpha, useTheme } from '@mui/material/styles';
import { DeveloperBoardOutlined } from '@mui/icons-material';
import { useDeployedTypeMetadata } from '@components/integrations/deployed/DeployedFacetSidebar';
import ConnectorUpdateChip from '@components/integrations/deployed/ConnectorUpdateChip';
import DeployedIntegrationPopover from '@components/integrations/deployed/DeployedIntegrationPopover';
import IngestionHealthTileBanner from '@components/integrations/deployed/IngestionHealthTileBanner';
import { DeployedIntegrationItem } from '@components/integrations/deployed/useDeployedIntegrations';
import { useFormatter } from '../../../../components/i18n';
import Card from '../../../../components/common/card/Card';
import IntegrationStatusChip from '@components/data/connectors/IntegrationStatusChip';
import { stopLinkNavigation } from '../../../../utils/domEvent';
import useHelper from '../../../../utils/hooks/useHelper';
import { paperBorder } from '../paperSurface';

interface MetricProps {
  label: string;
  value: string;
}

const Metric = ({ label, value }: MetricProps) => {
  const theme = useTheme();
  return (
    <Box sx={{ minWidth: 0 }}>
      <Typography
        sx={{
          fontSize: 11,
          fontWeight: 600,
          color: theme.palette.text.disabled,
          whiteSpace: 'nowrap',
        }}
      >
        {label}
      </Typography>
      <Typography
        sx={{
          fontSize: 13,
          fontWeight: 500,
          fontVariantNumeric: 'tabular-nums',
          whiteSpace: 'nowrap',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
        }}
      >
        {value}
      </Typography>
    </Box>
  );
};

export interface DeployedIntegrationCardProps {
  item: DeployedIntegrationItem;
  onChange: () => void;
}

const DeployedIntegrationCard = ({ item, onChange }: DeployedIntegrationCardProps) => {
  const { t_i18n, n, nsdt } = useFormatter();
  const theme = useTheme();
  const typeMetadata = useDeployedTypeMetadata();
  const { isFeatureEnable } = useHelper();
  const { label: typeLabel, icon: TypeIcon } = typeMetadata(item.sectionKey);
  const healthIssue = isFeatureEnable('INGESTION_HEALTH') ? item.healthIssue : null;

  return (
    <Box
      data-testid="integration-card"
      sx={{
        height: '100%',
        // Tiles without banner sit at the bottom of the row, under the room the banners of their neighbours take
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'flex-end',
        '& .MuiCard-root': {
          border: `1px solid ${paperBorder(theme)}`,
          // The banner closes the top edge
          ...(healthIssue && { borderTop: 'none', borderTopLeftRadius: 0, borderTopRightRadius: 0 }),
          transition: 'border-color 0.3s ease-in-out, box-shadow 0.3s ease-in-out',
        },
        // The glow wraps the banner and the card together
        '& .integration-tile': {
          transition: 'transform 0.3s ease-in-out, box-shadow 0.3s ease-in-out',
        },
        '&:hover .integration-tile': {
          transform: 'translateY(-2px)',
          boxShadow: `0 0 30px ${alpha(theme.palette.primary.main, 0.12)}`,
        },
        '&:hover .MuiCard-root': {
          borderColor: alpha(theme.palette.primary.main, 0.3),
        },
        // The bottom edge of the banner keeps its severity color
        '&:hover .integration-health-banner': {
          borderTopColor: alpha(theme.palette.primary.main, 0.3),
          borderLeftColor: alpha(theme.palette.primary.main, 0.3),
          borderRightColor: alpha(theme.palette.primary.main, 0.3),
        },
      }}
    >
      <Box className="integration-tile">
        {healthIssue && <IngestionHealthTileBanner issue={healthIssue} to={item.detailUrl} />}
        {/* Fixed height here: a percent height inside the auto-height tile would make the card grow by the banner height */}
        <Box sx={{ height: 220 }}>
          <Card
            // A real link, so ctrl/cmd and middle click open the detail in a new tab.
            to={item.detailUrl}
            sx={{
              height: '100%',
              borderRadius: 1,
              display: 'flex',
              flexDirection: 'column',
              gap: 1.5,
              cursor: 'pointer',
              alignItems: 'stretch',
            }}
          >
            <Stack
              direction="row"
              sx={{
                gap: 1.5,
                alignItems: 'flex-start',
                width: '100%',
              }}
            >
              <Box
                sx={{
                  height: 48,
                  width: 48,
                  flexShrink: 0,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  borderRadius: 1,
                  border: `1px solid ${alpha(theme.palette.text.primary, 0.1)}`,
                  backgroundColor: alpha(theme.palette.text.primary, 0.04),
                }}
              >
                {item.logo ? (
                  <img
                    style={{
                      height: 38,
                      width: 38,
                      objectFit: 'contain',
                      borderRadius: 4,
                    }}
                    src={item.logo}
                    alt={item.name}
                  />
                ) : (
                  <TypeIcon sx={{ fontSize: 24, color: theme.palette.primary.main }} />
                )}
              </Box>
              <Box sx={{ flex: 1, minWidth: 0 }}>
                <Stack
                  direction="row"
                  sx={{
                    alignItems: 'center',
                    gap: 1,
                  }}
                >
                  {/* Sentence case: the V7 design language avoids all-caps text. */}
                  <Typography
                    variant="body2"
                    sx={{
                      color: theme.palette.primary.main,
                      fontSize: 11,
                      fontWeight: 500,
                      whiteSpace: 'nowrap',
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                    }}
                  >
                    {typeLabel}
                  </Typography>
                  {item.isManaged && (
                    <Tooltip title={t_i18n('Managed by the connector manager')}>
                      <DeveloperBoardOutlined sx={{ fontSize: 15, color: theme.palette.primary.main }} />
                    </Tooltip>
                  )}
                </Stack>
                <Typography
                  sx={{
                    fontSize: 15,
                    fontWeight: 600,
                    lineHeight: 1.35,
                    display: '-webkit-box',
                    WebkitLineClamp: 2,
                    WebkitBoxOrient: 'vertical',
                    overflow: 'hidden',
                    wordBreak: 'break-word',
                  }}
                >
                  <Tooltip title={item.name} placement="bottom-start">
                    <span>{item.name}</span>
                  </Tooltip>
                </Typography>
              </Box>
              <DeployedIntegrationPopover item={item} onChange={onChange} />
            </Stack>

            <Box sx={{ flexGrow: 1, overflow: 'hidden', width: '100%' }}>
              {item.description && (
                <Typography
                  variant="body2"
                  sx={{
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    display: '-webkit-box',
                    WebkitLineClamp: 2,
                    WebkitBoxOrient: 'vertical',
                    lineHeight: 1.5,
                    color: theme.palette.text.secondary,
                    wordBreak: 'break-all',
                  }}
                >
                  {item.description}
                </Typography>
              )}
            </Box>

            <Stack
              direction="row"
              sx={{
                alignItems: 'flex-end',
                justifyContent: 'space-between',
                gap: 1.5,
                width: '100%',
                paddingTop: 1.5,
                borderTop: `1px solid ${alpha(theme.palette.text.primary, 0.05)}`,
              }}
            >
              <Stack
                direction="row"
                sx={{
                  gap: 2.5,
                  minWidth: 0,
                }}
              >
                {item.messagesCount != null && (
                  <Metric label={t_i18n('Messages')} value={n(item.messagesCount)} />
                )}
                {item.lastRunDate && (
                  <Metric label={t_i18n('Last run')} value={nsdt(item.lastRunDate)} />
                )}
                {!item.lastRunDate && item.lastSeenAt && (
                  <Metric label={t_i18n('Last seen')} value={nsdt(item.lastSeenAt)} />
                )}
                {!item.lastRunDate && !item.lastSeenAt && item.updatedAt && (
                  <Metric label={t_i18n('Modified')} value={nsdt(item.updatedAt)} />
                )}
                {item.userName && (
                  <Metric label={t_i18n('User')} value={item.userName} />
                )}
              </Stack>
              <Stack
                direction="column"
                onClick={stopLinkNavigation}
                onAuxClick={stopLinkNavigation}
                sx={{
                  alignItems: 'flex-end',
                  gap: 0.75,
                }}
              >
                {item.updateAvailable && <ConnectorUpdateChip version={item.latestCompatibleVersion} hasNewerIncompatibleVersion={item.hasNewerIncompatibleVersion} />}
                <IntegrationStatusChip status={item.status} />
              </Stack>
            </Stack>
          </Card>
        </Box>
      </Box>
    </Box>
  );
};

export default DeployedIntegrationCard;
