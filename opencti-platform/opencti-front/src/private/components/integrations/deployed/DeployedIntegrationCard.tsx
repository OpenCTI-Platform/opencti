import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Stack, Tooltip, Typography } from '@mui/material';
import Box from '@mui/material/Box';
import { alpha, useTheme } from '@mui/material/styles';
import { DeveloperBoardOutlined } from '@mui/icons-material';
import { useDeployedTypeMetadata } from '@components/integrations/deployed/DeployedFacetSidebar';
import DeployedIntegrationPopover from '@components/integrations/deployed/DeployedIntegrationPopover';
import { DeployedIntegrationItem } from '@components/integrations/deployed/useDeployedIntegrations';
import { useFormatter } from '../../../../components/i18n';
import Card from '../../../../components/common/card/Card';
import ItemBoolean from '../../../../components/ItemBoolean';

interface StatusDotProps {
  item: DeployedIntegrationItem;
  label: string;
}

const StatusDot = ({ item, label }: StatusDotProps) => {
  const theme = useTheme();
  let color = theme.palette.text.disabled;
  if (item.status === 'active') color = theme.palette.success.main;
  if (item.status === 'processing') color = theme.palette.warning.main;
  return (
    <Tooltip title={label}>
      <Box
        sx={{
          width: 8,
          height: 8,
          flexShrink: 0,
          borderRadius: '50%',
          backgroundColor: color,
          boxShadow: `0 0 6px ${color}`,
        }}
      />
    </Tooltip>
  );
};

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
          fontSize: 10,
          fontWeight: 600,
          letterSpacing: '0.08em',
          textTransform: 'uppercase',
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
  const navigate = useNavigate();
  const typeMetadata = useDeployedTypeMetadata();
  const { label: typeLabel, icon: TypeIcon } = typeMetadata(item.sectionKey);

  const statusText = (() => {
    if (item.status === 'processing') return t_i18n('Processing');
    if (item.status === 'active') return t_i18n('Active');
    return t_i18n('Inactive');
  })();

  const statusChip = (() => {
    if (item.status === 'processing') return <ItemBoolean status={undefined} label={statusText} />;
    return <ItemBoolean status={item.status === 'active'} label={statusText} />;
  })();

  return (
    <Box
      data-testid="integration-card"
      sx={{
        height: '100%',
        '& .MuiCard-root': {
          border: `1px solid ${alpha(theme.palette.text.primary, 0.08)}`,
          transition: 'transform 0.3s ease-in-out, border-color 0.3s ease-in-out, box-shadow 0.3s ease-in-out',
        },
        '&:hover .MuiCard-root': {
          transform: 'translateY(-2px)',
          borderColor: alpha(theme.palette.primary.main, 0.3),
          boxShadow: `0 0 30px ${alpha(theme.palette.primary.main, 0.12)}`,
        },
      }}
    >
      <Card
        onClick={() => navigate(item.detailUrl)}
        sx={{
          height: 220,
          borderRadius: 1,
          display: 'flex',
          flexDirection: 'column',
          gap: 1.5,
          cursor: 'pointer',
          alignItems: 'stretch',
        }}
      >
        <Stack direction="row" gap={1.5} alignItems="flex-start" sx={{ width: '100%' }}>
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
            <Stack direction="row" alignItems="center" gap={1}>
              <Typography
                variant="body2"
                sx={{
                  color: theme.palette.primary.main,
                  fontSize: 11,
                  fontWeight: 500,
                  letterSpacing: '0.06em',
                  textTransform: 'uppercase',
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
            <Stack direction="row" alignItems="center" gap={1}>
              <Tooltip title={item.name} placement="bottom-start">
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
                  {item.name}
                </Typography>
              </Tooltip>
              <StatusDot item={item} label={statusText} />
            </Stack>
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
          alignItems="flex-end"
          justifyContent="space-between"
          gap={1.5}
          sx={{
            width: '100%',
            paddingTop: 1.5,
            borderTop: `1px solid ${alpha(theme.palette.text.primary, 0.05)}`,
          }}
        >
          <Stack direction="row" gap={2.5} sx={{ minWidth: 0 }}>
            {item.messagesCount != null && (
              <Metric label={t_i18n('Messages')} value={n(item.messagesCount)} />
            )}
            {item.lastRunDate && (
              <Metric label={t_i18n('Last run')} value={nsdt(item.lastRunDate)} />
            )}
            {!item.lastRunDate && item.updatedAt && (
              // The connector updated_at is refreshed by pings: it is a last
              // seen date, unlike the feed entities modification date.
              <Metric
                label={item.kind === 'connector' ? t_i18n('Last seen') : t_i18n('Modified')}
                value={nsdt(item.updatedAt)}
              />
            )}
            {item.userName && (
              <Metric label={t_i18n('User')} value={item.userName} />
            )}
          </Stack>
          <Box onClick={(event) => event.stopPropagation()}>
            {statusChip}
          </Box>
        </Stack>
      </Card>
    </Box>
  );
};

export default DeployedIntegrationCard;
