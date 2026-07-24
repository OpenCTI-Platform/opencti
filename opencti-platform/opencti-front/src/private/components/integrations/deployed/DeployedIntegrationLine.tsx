import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Stack, Tooltip, Typography } from '@mui/material';
import Box from '@mui/material/Box';
import { alpha, useTheme } from '@mui/material/styles';
import { DeveloperBoardOutlined, ScheduleOutlined } from '@mui/icons-material';
import { useDeployedTypeMetadata } from '@components/integrations/deployed/DeployedFacetSidebar';
import DeployedIntegrationPopover from '@components/integrations/deployed/DeployedIntegrationPopover';
import { DeployedIntegrationItem } from '@components/integrations/deployed/useDeployedIntegrations';
import { useFormatter } from '../../../../components/i18n';
import ItemBoolean from '../../../../components/ItemBoolean';
import { EMPTY_VALUE } from '../../../../utils/String';

// Shared column geometry between the header row and the lines, so every
// section renders as a proper aligned table. Widths are percentages of the
// row so the table always fills the available space; the name column absorbs
// the rest. Metric columns collapse on small screens instead of squeezing
// the names.
const COLUMNS = {
  type: { width: '13%', minWidth: 110, display: { xs: 'none', sm: 'flex' } },
  description: { width: '18%', display: { xs: 'none', lg: 'flex' } },
  messages: { width: '8%', minWidth: 72, display: { xs: 'none', sm: 'flex' }, justifyContent: 'flex-end' },
  throughput: { width: '9%', minWidth: 84, display: { xs: 'none', md: 'flex' }, justifyContent: 'flex-end' },
  date: { width: '12%', minWidth: 130, display: { xs: 'none', md: 'flex' } },
  status: { width: '9%', minWidth: 84, display: 'flex' },
  actions: { width: 34, display: 'flex', justifyContent: 'center' },
} as const;

const cellSx = (column: keyof typeof COLUMNS) => ({
  ...COLUMNS[column],
  flexShrink: 0,
  alignItems: 'center',
});

// Column headers rendered once at the top of each section container.
export const DeployedIntegrationLinesHeader = () => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  const headerCellSx = {
    fontSize: 10,
    fontWeight: 600,
    textTransform: 'uppercase',
    letterSpacing: 0.5,
    color: theme.palette.text.secondary,
    lineHeight: 1,
  };
  return (
    <Box
      sx={{
        display: 'flex',
        alignItems: 'center',
        gap: 1.5,
        paddingInline: 1.5,
        paddingBlock: 1,
        backgroundColor: alpha(theme.palette.text.primary, 0.02),
        borderBottom: `1px solid ${alpha(theme.palette.text.primary, 0.08)}`,
      }}
    >
      <Typography component="div" sx={{ ...headerCellSx, flex: 1, minWidth: 0 }}>
        {t_i18n('Name')}
      </Typography>
      <Typography component="div" sx={{ ...headerCellSx, ...cellSx('type') }}>
        {t_i18n('Type')}
      </Typography>
      <Typography component="div" sx={{ ...headerCellSx, ...cellSx('description') }}>
        {t_i18n('Description')}
      </Typography>
      <Typography component="div" sx={{ ...headerCellSx, ...cellSx('messages') }}>
        {t_i18n('Messages')}
      </Typography>
      <Typography component="div" sx={{ ...headerCellSx, ...cellSx('throughput') }}>
        {t_i18n('Throughput')}
      </Typography>
      <Typography component="div" sx={{ ...headerCellSx, ...cellSx('date') }}>
        {t_i18n('Last activity')}
      </Typography>
      <Typography component="div" sx={{ ...headerCellSx, ...cellSx('status') }}>
        {t_i18n('Status')}
      </Typography>
      <Box sx={cellSx('actions')} />
    </Box>
  );
};

export interface DeployedIntegrationLineProps {
  item: DeployedIntegrationItem;
  onChange: () => void;
}

// Compact row variant of DeployedIntegrationCard for the lines view. Cells
// share their geometry with DeployedIntegrationLinesHeader so rows align.
const DeployedIntegrationLine = ({ item, onChange }: DeployedIntegrationLineProps) => {
  const { t_i18n, n, nsdt, rd } = useFormatter();
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

  const hasQueuedMessages = item.messagesCount != null && item.messagesCount > 0;

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
      {/* Name column: logo, name and managed flag. */}
      <Stack direction="row" alignItems="center" gap={1.5} sx={{ flex: 1, minWidth: 0 }}>
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
        <Tooltip title={item.name} placement="bottom-start">
          <Typography
            sx={{
              fontSize: 13,
              whiteSpace: 'nowrap',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
            }}
          >
            {item.name}
          </Typography>
        </Tooltip>
        {item.isManaged && (
          <Tooltip title={t_i18n('Managed by the connector manager')}>
            <DeveloperBoardOutlined sx={{ fontSize: 14, color: theme.palette.primary.main, flexShrink: 0 }} />
          </Tooltip>
        )}
      </Stack>
      {/* Type column. */}
      <Box sx={cellSx('type')}>
        <Typography
          sx={{
            fontSize: 12,
            color: theme.palette.primary.main,
            whiteSpace: 'nowrap',
            overflow: 'hidden',
            textOverflow: 'ellipsis',
          }}
        >
          {typeLabel}
        </Typography>
      </Box>
      {/* Description column. */}
      <Box sx={cellSx('description')}>
        <Typography
          sx={{
            fontSize: 12,
            color: theme.palette.text.secondary,
            whiteSpace: 'nowrap',
            overflow: 'hidden',
            textOverflow: 'ellipsis',
          }}
        >
          {item.description || EMPTY_VALUE}
        </Typography>
      </Box>
      {/* Messages column: queued messages badge (right-aligned numbers). */}
      <Box sx={cellSx('messages')}>
        {item.messagesCount != null ? (
          <Tooltip title={t_i18n('Queued messages')}>
            <Box
              component="span"
              sx={{
                paddingInline: 0.75,
                paddingBlock: '2px',
                borderRadius: 1,
                fontSize: 12,
                fontWeight: 600,
                fontVariantNumeric: 'tabular-nums',
                lineHeight: '16px',
                ...(hasQueuedMessages
                  ? {
                    color: theme.palette.primary.main,
                    backgroundColor: alpha(theme.palette.primary.main, 0.08),
                    border: `1px solid ${alpha(theme.palette.primary.main, 0.3)}`,
                  }
                  : {
                    color: theme.palette.text.secondary,
                    backgroundColor: alpha(theme.palette.text.primary, 0.04),
                    border: `1px solid ${alpha(theme.palette.text.primary, 0.08)}`,
                  }),
              }}
            >
              {n(item.messagesCount)}
            </Box>
          </Tooltip>
        ) : (
          <Typography sx={{ fontSize: 12, color: theme.palette.text.secondary }}>
            {EMPTY_VALUE}
          </Typography>
        )}
      </Box>
      {/* Throughput column: live bundles/second from the queue ack rate. */}
      <Box sx={cellSx('throughput')}>
        {item.throughputRate != null ? (
          <Tooltip title={t_i18n('Bundles processed')}>
            <Typography
              sx={{
                fontSize: 12,
                fontVariantNumeric: 'tabular-nums',
                whiteSpace: 'nowrap',
                color: item.throughputRate > 0 ? theme.palette.text.primary : theme.palette.text.secondary,
              }}
            >
              {`${n(item.throughputRate)}/s`}
            </Typography>
          </Tooltip>
        ) : (
          <Typography sx={{ fontSize: 12, color: theme.palette.text.secondary }}>
            {EMPTY_VALUE}
          </Typography>
        )}
      </Box>
      {/* Last activity column: relative time, exact datetime in the tooltip. */}
      <Box sx={cellSx('date')}>
        {lastDate ? (
          <Tooltip
            title={`${lastDateLabel}: ${nsdt(lastDate)}`}
            // Neutralize the global tooltip lowercasing: this is a sentence.
            slotProps={{ popper: { sx: { textTransform: 'none' } } }}
          >
            <Stack direction="row" alignItems="center" gap={0.5}>
              <ScheduleOutlined sx={{ fontSize: 13, color: theme.palette.text.secondary }} />
              <Typography sx={{ fontSize: 12, color: theme.palette.text.secondary, whiteSpace: 'nowrap' }}>
                {rd(lastDate)}
              </Typography>
            </Stack>
          </Tooltip>
        ) : (
          <Typography sx={{ fontSize: 12, color: theme.palette.text.secondary }}>
            {EMPTY_VALUE}
          </Typography>
        )}
      </Box>
      {/* Status column. */}
      <Box onClick={(event) => event.stopPropagation()} sx={cellSx('status')}>
        {item.status === 'processing'
          ? <ItemBoolean status={undefined} label={statusText} />
          : <ItemBoolean status={item.status === 'active'} label={statusText} />}
      </Box>
      {/* Actions column. */}
      <Box sx={cellSx('actions')}>
        <DeployedIntegrationPopover item={item} onChange={onChange} />
      </Box>
    </Box>
  );
};

export default DeployedIntegrationLine;
