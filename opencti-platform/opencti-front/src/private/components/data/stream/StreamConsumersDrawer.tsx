import React, { FunctionComponent, useCallback, useEffect, useState } from 'react';
import { graphql } from 'react-relay';
import Grid from '@mui/material/Grid';
import Paper from '@mui/material/Paper';
import Chip from '@mui/material/Chip';
import Box from '@mui/material/Box';
import Alert from '@mui/material/Alert';
import CircularProgress from '@mui/material/CircularProgress';
import Typography from '@mui/material/Typography';
import { useTheme } from '@mui/styles';
import Drawer from '../../common/drawer/Drawer';
import { fetchQuery } from '../../../../relay/environment';
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
        streamProductionRate
        consumerDeliveryRate
        consumerProcessingRate
        consumerResolutionRate
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
  streamProductionRate: number;
  consumerDeliveryRate: number;
  consumerProcessingRate: number;
  consumerResolutionRate: number;
  timeLag: number;
  estimatedOutOfDepth: number | null | undefined;
}

interface StreamConsumersDrawerProps {
  streamCollectionId: string;
  streamCollectionName: string;
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

const getOutOfDepthStatus = (
  estimatedOutOfDepth: number | null | undefined,
  t_i18n: (key: string) => string,
): { label: string; hexColor: string } => {
  if (!estimatedOutOfDepth) {
    return { label: t_i18n('Keeping up'), hexColor: '#2e7d32' };
  }
  if (estimatedOutOfDepth <= 0) {
    return { label: t_i18n('Out of depth'), hexColor: '#c62828' };
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

interface MetricBlockProps {
  label: string;
  value: string;
  theme: Theme;
}

const MetricBlock: FunctionComponent<MetricBlockProps> = ({ label, value, theme }) => (
  <Paper
    variant="outlined"
    className="paper-for-grid"
    sx={{
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      padding: theme.spacing(1.5),
      height: '100%',
    }}
  >
    <Typography
      variant="caption"
      sx={{ color: theme?.palette?.text?.secondary, textAlign: 'center' }}
    >
      {label}
    </Typography>
    <Typography
      variant="h6"
      sx={{ color: theme.palette.primary.main, fontWeight: 600, marginTop: 0.5 }}
    >
      {value}
    </Typography>
  </Paper>
);

const StreamConsumersDrawer: FunctionComponent<StreamConsumersDrawerProps> = ({
  streamCollectionId,
  streamCollectionName,
  open,
  onClose,
}) => {
  const { t_i18n, fldt } = useFormatter();
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
      <Paper
        key={consumer.connectionId}
        variant="outlined"
        sx={{
          padding: theme.spacing(2),
          marginBottom: theme.spacing(2),
        }}
      >
        {/* Card header: user info + depth status */}
        <Box
          sx={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            marginBottom: theme.spacing(2),
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
            style={{
              fontSize: 12,
              lineHeight: '12px',
              borderRadius: 4,
              height: 25,
              backgroundColor: `${depthStatus.hexColor}33`,
              color: depthStatus.hexColor,
              border: `2px solid ${depthStatus.hexColor}`,
            }}
          />
        </Box>
        {/* Metrics grid */}
        <Grid container spacing={2}>
          <Grid item xs={4}>
            <MetricBlock
              label={t_i18n('Stream rate')}
              value={`${consumer.streamProductionRate} /s`}
              theme={theme}
            />
          </Grid>

          <Grid item xs={4}>
            <MetricBlock
              label={t_i18n('Processing rate')}
              value={`${consumer.consumerProcessingRate} /s`}
              theme={theme}
            />
          </Grid>
          <Grid item xs={4}>
            <MetricBlock
              label={t_i18n('Resolution rate')}
              value={`${consumer.consumerResolutionRate} /s`}
              theme={theme}
            />
          </Grid>
          <Grid item xs={4}>
            <MetricBlock
              label={t_i18n('Delivery rate')}
              value={`${consumer.consumerDeliveryRate} /s`}
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
      </Paper>
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
