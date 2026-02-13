import React, { FunctionComponent, useCallback, useEffect, useState } from 'react';
import { graphql } from 'react-relay';
import Chip from '@mui/material/Chip';
import Box from '@mui/material/Box';
import Alert from '@mui/material/Alert';
import CircularProgress from '@mui/material/CircularProgress';
import Tooltip from '@mui/material/Tooltip';
import Typography from '@mui/material/Typography';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import Divider from '@mui/material/Divider';
import { InfoOutlined } from '@mui/icons-material';
import { useTheme } from '@mui/styles';
import Drawer from '../../common/drawer/Drawer';
import { fetchQuery } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import { FIVE_SECONDS } from '../../../../utils/Time';
import type { Theme } from '../../../../components/Theme';
import { SyncConsumersDrawerQuery$data } from './__generated__/SyncConsumersDrawerQuery.graphql';

const syncConsumersQuery = graphql`
  query SyncConsumersDrawerQuery($id: String!) {
    synchronizer(id: $id) {
      id
      name
      consumer_metrics {
        connectionId
        connectedAt
        lastEventId
        lastEventDate
        productionRate
        deliveryRate
        processingRate
        resolutionRate
        timeLag
        estimatedOutOfDepth
      }
    }
  }
`;

interface SyncConsumerMetrics {
  connectionId: string;
  connectedAt: string;
  lastEventId: string;
  lastEventDate: string | null;
  productionRate: number;
  deliveryRate: number;
  processingRate: number;
  resolutionRate: number;
  timeLag: number;
  estimatedOutOfDepth: number | null | undefined;
}

interface SyncConsumersDrawerProps {
  syncId: string;
  syncName: string;
  open: boolean;
  onClose: () => void;
}

const formatDuration = (seconds: number): string => {
  if (seconds <= 0) return '0s';
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const secs = Math.floor(seconds % 60);
  const parts: string[] = [];
  if (days > 0) parts.push(`${days}d`);
  if (hours > 0) parts.push(`${hours}h`);
  if (minutes > 0) parts.push(`${minutes}m`);
  if (secs > 0 || parts.length === 0) parts.push(`${secs}s`);
  return parts.join(' ');
};

const eventIdToDate = (eventId: string, dateFormatter: (date: string | Date) => string): string | null => {
  if (!eventId) return null;
  const ts = parseInt(eventId.split('-')[0], 10);
  if (Number.isNaN(ts) || ts <= 0) return null;
  return dateFormatter(new Date(ts).toISOString());
};

const getOutOfDepthStatus = (
  estimatedOutOfDepth: number | null | undefined,
  t_i18n: (key: string) => string,
): { label: string; hexColor: string } => {
  if (!estimatedOutOfDepth) {
    return { label: t_i18n('Healthy'), hexColor: '#2e7d32' };
  }
  const ONE_HOUR = 3600;
  const ONE_DAY = 86400;
  if (estimatedOutOfDepth < ONE_HOUR) {
    return { label: formatDuration(estimatedOutOfDepth), hexColor: '#c62828' };
  }
  if (estimatedOutOfDepth < ONE_DAY) {
    return { label: formatDuration(estimatedOutOfDepth), hexColor: '#d84315' };
  }
  return { label: formatDuration(estimatedOutOfDepth), hexColor: '#2e7d32' };
};

interface MetricRowProps {
  label: string;
  value: string | React.ReactNode;
  tooltip?: string;
  theme: Theme;
}

const MetricRow: FunctionComponent<MetricRowProps> = ({ label, value, tooltip, theme }) => {
  return (
    <ListItem sx={{ py: 1, px: 0 }}>
      <ListItemText
        primary={label}
        primaryTypographyProps={{ variant: 'body2', sx: { color: theme?.palette?.text?.secondary } }}
        sx={{ flex: '0 0 auto', minWidth: 160 }}
      />
      <Box sx={{ ml: 'auto', display: 'flex', alignItems: 'center', gap: 0.5 }}>
        <Typography variant="body2" sx={{ fontWeight: 600 }}>
          {value}
        </Typography>
        {tooltip && (
          <Tooltip title={tooltip} arrow>
            <InfoOutlined sx={{ fontSize: 16, color: theme?.palette?.text?.secondary, cursor: 'pointer' }} />
          </Tooltip>
        )}
      </Box>
    </ListItem>
  );
};

const SyncConsumersDrawer: FunctionComponent<SyncConsumersDrawerProps> = ({
  syncId,
  syncName,
  open,
  onClose,
}) => {
  const { t_i18n, fldt, nsdt } = useFormatter();
  const theme = useTheme<Theme>();
  const [metrics, setMetrics] = useState<SyncConsumerMetrics | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchMetrics = useCallback(() => {
    if (!open || !syncId) return;
    fetchQuery(syncConsumersQuery, { id: syncId })
      .toPromise()
      .then((data) => {
        const result = data as SyncConsumersDrawerQuery$data;
        if (result?.synchronizer?.consumer_metrics) {
          setMetrics(result.synchronizer.consumer_metrics as SyncConsumerMetrics);
        } else {
          setMetrics(null);
        }
        setLoading(false);
      })
      .catch(() => {
        setLoading(false);
      });
  }, [syncId, open]);

  useEffect(() => {
    if (open) {
      setLoading(true);
      fetchMetrics();
      const timer = setInterval(fetchMetrics, FIVE_SECONDS);
      return () => clearInterval(timer);
    }
    return undefined;
  }, [open, fetchMetrics]);

  const renderMetrics = (consumer: SyncConsumerMetrics) => {
    const depthStatus = getOutOfDepthStatus(consumer.estimatedOutOfDepth, t_i18n);
    return (
      <List disablePadding>
        <ListItem sx={{ py: 1, px: 0 }}>
          <ListItemText
            primary={t_i18n('Status')}
            primaryTypographyProps={{ variant: 'body2', sx: { color: theme?.palette?.text?.secondary } }}
            sx={{ flex: '0 0 auto', minWidth: 160 }}
          />
          <Box sx={{ ml: 'auto' }}>
            <Chip
              label={depthStatus.label}
              style={{
                fontSize: 12,
                lineHeight: '12px',
                borderRadius: 4,
                height: 25,
                width: 125,
                textAlign: 'center',
                backgroundColor: `${depthStatus.hexColor}33`,
                color: depthStatus.hexColor,
                border: `2px solid ${depthStatus.hexColor}`,
              }}
            />
          </Box>
        </ListItem>
        <Divider />
        <MetricRow
          label={t_i18n('Connected since')}
          value={fldt(consumer.connectedAt)}
          theme={theme}
        />
        <Divider />
        <MetricRow
          label={t_i18n('Stream rate')}
          value={`${consumer.productionRate} /s`}
          theme={theme}
        />
        <Divider />
        <MetricRow
          label={t_i18n('Processing rate')}
          value={`${consumer.processingRate} /s`}
          theme={theme}
        />
        <Divider />
        <MetricRow
          label={t_i18n('Resolution rate')}
          value={`${consumer.resolutionRate} /s`}
          theme={theme}
        />
        <Divider />
        <MetricRow
          label={t_i18n('Reception rate')}
          value={`${consumer.deliveryRate} /s`}
          theme={theme}
        />
        <Divider />
        <MetricRow
          label={t_i18n('Last event ID')}
          value={eventIdToDate(consumer.lastEventId, nsdt) ?? '-'}
          tooltip={consumer.lastEventId || undefined}
          theme={theme}
        />
        <Divider />
        <MetricRow
          label={t_i18n('Time lag')}
          value={consumer.timeLag > 0 ? formatDuration(consumer.timeLag) : t_i18n('None')}
          theme={theme}
        />
      </List>
    );
  };

  const drawerContent = () => {
    if (loading && !metrics) {
      return (
        <Box display="flex" justifyContent="center" p={4}>
          <CircularProgress />
        </Box>
      );
    }
    if (!loading && !metrics) {
      return (
        <Alert severity="info" variant="outlined">
          {t_i18n('No producer metrics available for this synchronizer')}
        </Alert>
      );
    }
    if (metrics) {
      return renderMetrics(metrics);
    }
    return null;
  };

  return (
    <Drawer
      title={`${t_i18n('Producer metrics')} - ${syncName}`}
      open={open}
      onClose={onClose}
    >
      {drawerContent()}
    </Drawer>
  );
};

export default SyncConsumersDrawer;
