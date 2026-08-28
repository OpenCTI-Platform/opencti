import React, { FunctionComponent, useCallback, useEffect, useState } from 'react';
import { Chip, Paper } from '@filigran/design-system';
import { graphql } from 'react-relay';
import Accordion from '@mui/material/Accordion';
import AccordionSummary from '@mui/material/AccordionSummary';
import AccordionDetails from '@mui/material/AccordionDetails';
import { ExpandMore, InfoOutlined } from '@mui/icons-material';
import Grid from '@mui/material/Grid';
import Box from '@mui/material/Box';
import Alert from '@mui/material/Alert';
import CircularProgress from '@mui/material/CircularProgress';
import Tooltip from '@mui/material/Tooltip';
import Typography from '@mui/material/Typography';
import { useTheme } from '@mui/styles';
import Drawer from '../../common/drawer/Drawer';
import { fetchQuery, MESSAGING$ } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import { FIVE_SECONDS } from '../../../../utils/Time';
import type { Theme } from '../../../../components/Theme';
import { StreamConsumersDrawerQuery$data } from '@components/data/stream/__generated__/StreamConsumersDrawerQuery.graphql';

const streamConsumersQuery = graphql`
  query StreamConsumersDrawerQuery($id: String!) {
    streamCollection(id: $id) {
      id
      name
      consumers {
        connectionId
        userId
        userEmail
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

interface StreamCollectionConsumer {
  connectionId: string;
  userId: string | null;
  userEmail: string | null | undefined;
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

interface StreamConsumersDrawerProps {
  streamCollectionId?: string;
  streamCollectionName: string | null | undefined;
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
): { label: string; severity: 'low' | 'high' | 'critical' } => {
  if (!estimatedOutOfDepth) {
    return { label: t_i18n('Healthy'), severity: 'low' };
  }
  const ONE_HOUR = 3600;
  const ONE_DAY = 86400;
  if (estimatedOutOfDepth < ONE_HOUR) {
    return { label: formatDuration(estimatedOutOfDepth), severity: 'critical' };
  }
  if (estimatedOutOfDepth < ONE_DAY) {
    return { label: formatDuration(estimatedOutOfDepth), severity: 'high' };
  }
  return { label: formatDuration(estimatedOutOfDepth), severity: 'low' };
};

interface MetricBlockProps {
  label: string;
  value: string;
  theme: Theme;
  tooltip?: string;
}

const MetricBlock: FunctionComponent<MetricBlockProps> = ({ label, value, theme, tooltip }) => {
  return (
    // FDS-WORKAROUND #16: `h-full` loses to the product's unlayered `.paper-for-grid`; height stays inline — see fds-migration/LIBRARY-FEEDBACK.md #16
    <Paper
      padding={16}
      className="paper-for-grid flex flex-col items-center justify-center"
      style={{ height: '100%' }}
    >
      <Typography
        variant="caption"
        sx={{ color: theme?.palette?.text?.secondary, textAlign: 'center' }}
      >
        {label}
      </Typography>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, marginTop: 0.5 }}>
        <Typography
          variant="body1"
          sx={{ fontWeight: 600 }}
        >
          {value}
        </Typography>
        {tooltip && (
          <Tooltip title={tooltip} arrow>
            <InfoOutlined sx={{ fontSize: 16, color: theme?.palette?.text?.secondary, cursor: 'pointer' }} />
          </Tooltip>
        )}
      </Box>
    </Paper>
  );
};

const StreamConsumersDrawer: FunctionComponent<StreamConsumersDrawerProps> = ({
  streamCollectionId,
  streamCollectionName,
  open,
  onClose,
}) => {
  const { t_i18n, fldt, nsdt } = useFormatter();
  const theme = useTheme<Theme>();
  const [consumers, setConsumers] = useState<readonly StreamCollectionConsumer[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchConsumers = useCallback(() => {
    if (!open || !streamCollectionId) return;
    fetchQuery(streamConsumersQuery, { id: streamCollectionId })
      .toPromise()
      .then((data) => {
        const result = data as StreamConsumersDrawerQuery$data;
        if (result?.streamCollection?.consumers) {
          setConsumers(result.streamCollection.consumers);
        } else {
          setConsumers([]);
        }
        setLoading(false);
      })
      .catch(() => {
        MESSAGING$.notifyError(t_i18n('Error loading stream collection consumers'));
        setLoading(false);
      });
  }, [streamCollectionId, open]);

  useEffect(() => {
    if (open) {
      setLoading(true);
      fetchConsumers();
      const timer = setInterval(fetchConsumers, FIVE_SECONDS);
      return () => clearInterval(timer);
    }
    return undefined;
  }, [open, fetchConsumers]);

  const renderConsumerCard = (consumer: StreamCollectionConsumer) => {
    const depthStatus = getOutOfDepthStatus(consumer.estimatedOutOfDepth, t_i18n);
    return (
      <Accordion
        key={consumer.connectionId}
        defaultExpanded={true}
        variant="outlined"
        disableGutters
        sx={{
          marginBottom: theme.spacing(1),
          '&:before': { display: 'none' },
          borderRadius: 1,
        }}
      >
        <AccordionSummary
          expandIcon={<ExpandMore />}
          sx={{ minHeight: 56 }}
        >
          <Box
            sx={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              width: '100%',
              paddingRight: theme.spacing(1),
            }}
          >
            <Box>
              <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>
                {consumer.userEmail || consumer.userId}
              </Typography>
              <Typography variant="caption" sx={{ color: theme?.palette?.text?.secondary }}>
                {t_i18n('Connected since')} {fldt(consumer.connectedAt)}
              </Typography>
            </Box>
            <Chip
              label={depthStatus.label}
              severity={depthStatus.severity}
            />
          </Box>
        </AccordionSummary>
        <AccordionDetails sx={{ paddingTop: 0 }}>
          <Grid container spacing={2}>
            <Grid item xs={4}>
              <MetricBlock
                label={t_i18n('Stream rate')}
                value={`${consumer.productionRate} /s`}
                theme={theme}
              />
            </Grid>
            <Grid item xs={4}>
              <MetricBlock
                label={t_i18n('Processing rate')}
                value={`${consumer.processingRate} /s`}
                theme={theme}
              />
            </Grid>
            <Grid item xs={4}>
              <MetricBlock
                label={t_i18n('Resolution rate')}
                value={`${consumer.resolutionRate} /s`}
                theme={theme}
              />
            </Grid>
            <Grid item xs={4}>
              <MetricBlock
                label={t_i18n('Delivery rate')}
                value={`${consumer.deliveryRate} /s`}
                theme={theme}
              />
            </Grid>
            <Grid item xs={4}>
              <MetricBlock
                label={t_i18n('Last event ID')}
                value={eventIdToDate(consumer.lastEventId, nsdt) ?? '-'}
                tooltip={consumer.lastEventId || undefined}
                theme={theme}
              />
            </Grid>
            <Grid item xs={4}>
              <MetricBlock
                label={t_i18n('Time lag')}
                value={consumer.timeLag > 0 ? formatDuration(consumer.timeLag) : t_i18n('None')}
                theme={theme}
              />
            </Grid>
          </Grid>
        </AccordionDetails>
      </Accordion>
    );
  };

  const consumerContent = () => {
    if (loading && consumers.length === 0) {
      return (
        <Box display="flex" justifyContent="center" p={4}>
          <CircularProgress />
        </Box>
      );
    }
    if (!loading && consumers.length === 0) {
      return (
        <Alert severity="info" variant="outlined">
          {t_i18n('No consumers connected to this stream')}
        </Alert>
      );
    }
    return (
      <Box>
        {consumers.map((consumer) => renderConsumerCard(consumer))}
      </Box>
    );
  };

  return (
    <Drawer
      title={`${t_i18n('Stream consumers')} - ${streamCollectionName}`}
      open={open}
      onClose={onClose}
    >
      {consumerContent()}
    </Drawer>
  );
};

export default StreamConsumersDrawer;
