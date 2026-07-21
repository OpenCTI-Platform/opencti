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
import ItemBoolean from '../../../../components/ItemBoolean';

export interface DeployedIntegrationLineProps {
  item: DeployedIntegrationItem;
  onChange: () => void;
}

// Compact row variant of DeployedIntegrationCard for the lines view.
const DeployedIntegrationLine = ({ item, onChange }: DeployedIntegrationLineProps) => {
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

  const lastDate = item.lastRunDate ?? item.updatedAt;
  const lastDateLabel = (() => {
    if (item.lastRunDate) return t_i18n('Last run');
    // The connector updated_at is refreshed by pings: it is a last seen date.
    return item.kind === 'connector' ? t_i18n('Last seen') : t_i18n('Modified');
  })();

  return (
    <Box
      data-testid="integration-line"
      onClick={() => navigate(item.detailUrl)}
      sx={{
        display: 'flex',
        alignItems: 'center',
        gap: 1.5,
        paddingInline: 1.5,
        paddingBlock: 0.75,
        cursor: 'pointer',
        transition: 'background-color 0.2s ease-in-out',
        '&:hover': {
          backgroundColor: theme.palette.action.hover,
        },
        '& + &': {
          borderTop: `1px solid ${alpha(theme.palette.text.primary, 0.05)}`,
        },
      }}
    >
      <Box
        sx={{
          height: 32,
          width: 32,
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
            style={{ height: 24, width: 24, objectFit: 'contain', borderRadius: 3 }}
            src={item.logo}
            alt={item.name}
          />
        ) : (
          <TypeIcon sx={{ fontSize: 18, color: theme.palette.primary.main }} />
        )}
      </Box>
      <Stack direction="row" alignItems="center" gap={1} sx={{ flex: 1, minWidth: 0 }}>
        <Tooltip title={item.name} placement="bottom-start">
          <Typography
            sx={{
              fontSize: 13,
              fontWeight: 600,
              whiteSpace: 'nowrap',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              maxWidth: '40%',
              flexShrink: 0,
            }}
          >
            {item.name}
          </Typography>
        </Tooltip>
        <Typography
          variant="body2"
          sx={{
            fontSize: 12,
            color: theme.palette.primary.main,
            whiteSpace: 'nowrap',
            flexShrink: 0,
          }}
        >
          {typeLabel}
        </Typography>
        {item.isManaged && (
          <Tooltip title={t_i18n('Managed by the connector manager')}>
            <DeveloperBoardOutlined sx={{ fontSize: 14, color: theme.palette.primary.main, flexShrink: 0 }} />
          </Tooltip>
        )}
        {item.description && (
          <Typography
            variant="body2"
            sx={{
              fontSize: 12,
              color: theme.palette.text.secondary,
              whiteSpace: 'nowrap',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
            }}
          >
            {item.description}
          </Typography>
        )}
      </Stack>
      <Stack direction="row" alignItems="center" gap={2.5} sx={{ flexShrink: 0 }}>
        {item.messagesCount != null && (
          <Typography sx={{ fontSize: 12, color: theme.palette.text.secondary, fontVariantNumeric: 'tabular-nums', whiteSpace: 'nowrap' }}>
            {`${t_i18n('Messages')}: ${n(item.messagesCount)}`}
          </Typography>
        )}
        {lastDate && (
          <Typography sx={{ fontSize: 12, color: theme.palette.text.secondary, fontVariantNumeric: 'tabular-nums', whiteSpace: 'nowrap' }}>
            {`${lastDateLabel}: ${nsdt(lastDate)}`}
          </Typography>
        )}
        <Box onClick={(event) => event.stopPropagation()}>
          {item.status === 'processing'
            ? <ItemBoolean status={undefined} label={statusText} />
            : <ItemBoolean status={item.status === 'active'} label={statusText} />}
        </Box>
        <DeployedIntegrationPopover item={item} onChange={onChange} />
      </Stack>
    </Box>
  );
};

export default DeployedIntegrationLine;
