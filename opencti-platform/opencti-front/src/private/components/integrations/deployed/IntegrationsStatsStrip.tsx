import React, { Suspense, useEffect, useRef } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery, useQueryLoader } from 'react-relay';
import { Stack, Typography } from '@mui/material';
import { alpha, useTheme } from '@mui/material/styles';
import { DnsOutlined, DownloadOutlined, EngineeringOutlined, SpeedOutlined, StorageOutlined, UploadOutlined } from '@mui/icons-material';
import type { SvgIconComponent } from '@mui/icons-material';
import { interval } from 'rxjs';
import { IntegrationsStatsStripQuery } from './__generated__/IntegrationsStatsStripQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import { EMPTY_VALUE } from '../../../../utils/String';
import { FIVE_SECONDS } from '../../../../utils/Time';
import useGranted, { MODULES } from '../../../../utils/hooks/useGranted';

const interval$ = interval(FIVE_SECONDS);

const integrationsStatsStripQuery = graphql`
  query IntegrationsStatsStripQuery {
    elasticSearchMetrics {
      docs {
        count
      }
      search {
        query_total
      }
      indexing {
        index_total
        delete_total
      }
    }
    rabbitMQMetrics {
      consumers
      overview {
        queue_totals {
          messages
        }
        message_stats {
          ack_details {
            rate
          }
        }
      }
    }
  }
`;

interface StatChipProps {
  icon: SvgIconComponent;
  value: string;
  label: string;
}

const StatChip = ({ icon: Icon, value, label }: StatChipProps) => {
  const theme = useTheme();
  return (
    <Stack
      direction="row"
      alignItems="center"
      gap={0.75}
      sx={{
        paddingInline: 1.25,
        paddingBlock: 0.5,
        borderRadius: 1,
        border: `1px solid ${alpha(theme.palette.text.primary, 0.1)}`,
        backgroundColor: theme.palette.background.paper,
      }}
    >
      <Icon sx={{ fontSize: 15, color: theme.palette.primary.main }} />
      <Typography sx={{ fontSize: 13, fontWeight: 600, fontVariantNumeric: 'tabular-nums' }}>
        {value}
      </Typography>
      <Typography sx={{ fontSize: 12, color: theme.palette.text.secondary, whiteSpace: 'nowrap' }}>
        {label}
      </Typography>
    </Stack>
  );
};

interface StatsStripContentProps {
  queryRef: PreloadedQuery<IntegrationsStatsStripQuery>;
}

const StatsStripContent = ({ queryRef }: StatsStripContentProps) => {
  const { t_i18n, n } = useFormatter();
  const data = usePreloadedQuery(integrationsStatsStripQuery, queryRef);
  const lastReadOperations = useRef(0);
  const lastWriteOperations = useRef(0);

  const toNumber = (value: unknown): number | null => {
    if (value == null) return null;
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : null;
  };

  const consumers = toNumber(data.rabbitMQMetrics?.consumers);
  const queuedBundles = toNumber(data.rabbitMQMetrics?.overview?.queue_totals?.messages);
  const ackRate = toNumber(data.rabbitMQMetrics?.overview?.message_stats?.ack_details?.rate);
  const docsCount = toNumber(data.elasticSearchMetrics?.docs?.count);

  const currentReadOperations = data.elasticSearchMetrics?.search
    ? Number(data.elasticSearchMetrics.search.query_total)
    : null;
  const currentWriteOperations = data.elasticSearchMetrics?.indexing
    ? Number(data.elasticSearchMetrics.indexing.index_total) + Number(data.elasticSearchMetrics.indexing.delete_total)
    : null;

  let readOperations: number | null = null;
  let writeOperations: number | null = null;
  if (lastReadOperations.current !== 0 && currentReadOperations != null) {
    readOperations = Math.max(0, (currentReadOperations - lastReadOperations.current) / 5);
  }
  if (lastWriteOperations.current !== 0 && currentWriteOperations != null) {
    writeOperations = Math.max(0, (currentWriteOperations - lastWriteOperations.current) / 5);
  }

  useEffect(() => {
    if (currentReadOperations != null) lastReadOperations.current = currentReadOperations;
    if (currentWriteOperations != null) lastWriteOperations.current = currentWriteOperations;
  });

  const safeValue = (value: number | null | undefined, suffix = ''): string => {
    return value != null ? `${n(value)}${suffix}` : EMPTY_VALUE;
  };

  return (
    <Stack direction="row" flexWrap="wrap" gap={1}>
      <StatChip icon={EngineeringOutlined} value={safeValue(consumers)} label={t_i18n('Connected workers')} />
      <StatChip icon={DnsOutlined} value={safeValue(queuedBundles)} label={t_i18n('Queued bundles')} />
      <StatChip icon={SpeedOutlined} value={safeValue(ackRate, '/s')} label={t_i18n('Bundles processed')} />
      <StatChip icon={DownloadOutlined} value={safeValue(readOperations, '/s')} label={t_i18n('Read operations')} />
      <StatChip icon={UploadOutlined} value={safeValue(writeOperations, '/s')} label={t_i18n('Write operations')} />
      <StatChip icon={StorageOutlined} value={safeValue(docsCount)} label={t_i18n('Total number of documents')} />
    </Stack>
  );
};

// Compact platform-health strip: workers, queues and search engine metrics,
// refreshed every five seconds (replaces the legacy monitoring cards).
const IntegrationsStatsStrip = () => {
  const isConnectorReader = useGranted([MODULES]);
  const [queryRef, loadQuery] = useQueryLoader<IntegrationsStatsStripQuery>(integrationsStatsStripQuery);

  useEffect(() => {
    if (!isConnectorReader) return undefined;
    loadQuery({}, { fetchPolicy: 'store-and-network' });
    const subscription = interval$.subscribe(() => {
      loadQuery({}, { fetchPolicy: 'network-only' });
    });
    return () => subscription.unsubscribe();
  }, []);

  if (!isConnectorReader || !queryRef) return null;

  return (
    <Suspense fallback={null}>
      <StatsStripContent queryRef={queryRef} />
    </Suspense>
  );
};

export default IntegrationsStatsStrip;
