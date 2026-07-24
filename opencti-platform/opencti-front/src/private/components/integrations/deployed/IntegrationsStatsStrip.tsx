import React, { Fragment, Suspense, useEffect, useRef } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery, useQueryLoader } from 'react-relay';
import { Box, Stack, Tooltip, Typography } from '@mui/material';
import { alpha, useTheme } from '@mui/material/styles';
import { Link } from 'react-router-dom';
import { DnsOutlined, DownloadOutlined, EngineeringOutlined, RocketLaunchOutlined, SpeedOutlined, StorageOutlined, SwapVertOutlined, UploadOutlined } from '@mui/icons-material';
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

interface StripMetrics {
  queuedBundles: number | null;
  consumers: number | null;
  ackRate: number | null;
  readOperations: number | null;
  writeOperations: number | null;
  docsCount: number | null;
}

const EMPTY_METRICS: StripMetrics = {
  queuedBundles: null,
  consumers: null,
  ackRate: null,
  readOperations: null,
  writeOperations: null,
  docsCount: null,
};

const NODE_SIZE = 44;

interface FlowNodeProps {
  icon: SvgIconComponent;
  value: React.ReactNode;
  label: string;
  // Optional deep link to the matching view.
  to?: string;
}

// One glowing circular step of the ingestion pipeline: icon in a ring, then
// the live value and its label underneath (XTM One flow-ribbon style).
const FlowNode = ({ icon: Icon, value, label, to }: FlowNodeProps) => {
  const theme = useTheme();
  const content = (
    <>
      <Box
        className="flow-node-circle"
        sx={{
          width: NODE_SIZE,
          height: NODE_SIZE,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          borderRadius: '50%',
          border: `1px solid ${alpha(theme.palette.primary.main, 0.5)}`,
          backgroundColor: alpha(theme.palette.primary.main, 0.06),
          boxShadow: `0 0 18px ${alpha(theme.palette.primary.main, 0.2)}`,
          transition: 'border-color 0.2s ease-in-out, box-shadow 0.2s ease-in-out',
        }}
      >
        <Icon sx={{ fontSize: 18, color: theme.palette.primary.main }} />
      </Box>
      <Stack alignItems="center" gap={0.5}>
        <Typography
          component="div"
          sx={{
            fontSize: 14,
            fontWeight: 700,
            fontVariantNumeric: 'tabular-nums',
            lineHeight: 1,
          }}
        >
          {value}
        </Typography>
        <Typography
          component="div"
          sx={{
            fontSize: 11,
            color: theme.palette.text.secondary,
            lineHeight: 1,
            whiteSpace: 'nowrap',
          }}
        >
          {label}
        </Typography>
      </Stack>
    </>
  );
  if (to) {
    return (
      <Stack
        component={Link}
        to={to}
        alignItems="center"
        gap={1}
        sx={{
          flexShrink: 0,
          textDecoration: 'none',
          color: 'inherit',
          '&:hover .flow-node-circle': {
            borderColor: theme.palette.primary.main,
            boxShadow: `0 0 22px ${alpha(theme.palette.primary.main, 0.45)}`,
          },
        }}
      >
        {content}
      </Stack>
    );
  }
  return (
    <Stack alignItems="center" gap={1} sx={{ flexShrink: 0 }}>
      {content}
    </Stack>
  );
};

// The connecting line between two pipeline nodes, with a small glowing dot
// flowing left to right to picture the data stream.
const FlowLink = ({ index }: { index: number }) => {
  const theme = useTheme();
  return (
    <Box
      sx={{
        position: 'relative',
        flex: 1,
        minWidth: 24,
        height: '1px',
        marginInline: 1.5,
        // Align the line with the center of the circles (top-aligned nodes).
        alignSelf: 'flex-start',
        marginTop: `${NODE_SIZE / 2}px`,
        background: `linear-gradient(90deg, transparent, ${alpha(theme.palette.primary.main, 0.35)}, transparent)`,
      }}
    >
      <Box
        sx={{
          position: 'absolute',
          top: '50%',
          width: 5,
          height: 5,
          borderRadius: '50%',
          backgroundColor: theme.palette.primary.main,
          boxShadow: `0 0 6px ${theme.palette.primary.main}`,
          transform: 'translateY(-50%)',
          animation: 'integrationsFlowDot 2.8s linear infinite',
          animationDelay: `${index * 0.45}s`,
          '@keyframes integrationsFlowDot': {
            '0%': { left: 0, opacity: 0 },
            '12%': { opacity: 1 },
            '88%': { opacity: 1 },
            '100%': { left: '100%', opacity: 0 },
          },
          '@media (prefers-reduced-motion: reduce)': {
            display: 'none',
          },
        }}
      />
    </Box>
  );
};

interface FlowRibbonProps {
  deployedCount: number;
  metrics: StripMetrics;
}

// The full ingestion pipeline at a glance: deployed integrations feeding the
// queue, consumed by workers, processed into operations and stored documents.
const FlowRibbon = ({ deployedCount, metrics }: FlowRibbonProps) => {
  const { t_i18n, n } = useFormatter();
  const theme = useTheme();

  const safeValue = (value: number | null, suffix = ''): string => {
    return value != null ? `${n(value)}${suffix}` : EMPTY_VALUE;
  };

  // Read/write rates share one "Operations" node: two compact stacked rows.
  const operationsValue = (
    <Stack alignItems="flex-start" gap={0.5}>
      <Tooltip title={t_i18n('Read operations')}>
        <Stack direction="row" alignItems="center" gap={0.5}>
          <DownloadOutlined sx={{ fontSize: 11, color: theme.palette.primary.main }} />
          <Box component="span" sx={{ fontSize: 11, lineHeight: 1 }}>{safeValue(metrics.readOperations, '/s')}</Box>
        </Stack>
      </Tooltip>
      <Tooltip title={t_i18n('Write operations')}>
        <Stack direction="row" alignItems="center" gap={0.5}>
          <UploadOutlined sx={{ fontSize: 11, color: theme.palette.primary.main }} />
          <Box component="span" sx={{ fontSize: 11, lineHeight: 1 }}>{safeValue(metrics.writeOperations, '/s')}</Box>
        </Stack>
      </Tooltip>
    </Stack>
  );

  // Ids are stable across locales: used as React keys (labels are translated).
  const nodes: (FlowNodeProps & { id: string })[] = [
    {
      id: 'deployed',
      icon: RocketLaunchOutlined,
      value: safeValue(deployedCount),
      label: t_i18n('Deployed integrations'),
      to: '/dashboard/integrations/deployed',
    },
    { id: 'queued', icon: DnsOutlined, value: safeValue(metrics.queuedBundles), label: t_i18n('Queued bundles') },
    { id: 'workers', icon: EngineeringOutlined, value: safeValue(metrics.consumers), label: t_i18n('Connected workers') },
    { id: 'processed', icon: SpeedOutlined, value: safeValue(metrics.ackRate, '/s'), label: t_i18n('Bundles processed') },
    { id: 'operations', icon: SwapVertOutlined, value: operationsValue, label: t_i18n('Operations') },
    { id: 'documents', icon: StorageOutlined, value: safeValue(metrics.docsCount), label: t_i18n('Total documents') },
  ];

  return (
    <Stack
      direction="row"
      alignItems="flex-start"
      sx={{
        marginTop: 2.5,
        paddingTop: 2.5,
        paddingInline: 1,
        borderTop: `1px solid ${alpha(theme.palette.text.primary, 0.05)}`,
      }}
    >
      {nodes.map(({ id, ...node }, i) => (
        <Fragment key={id}>
          <FlowNode {...node} />
          {i < nodes.length - 1 && <FlowLink index={i} />}
        </Fragment>
      ))}
    </Stack>
  );
};

interface StatsStripContentProps {
  queryRef: PreloadedQuery<IntegrationsStatsStripQuery>;
  deployedCount: number;
}

const StatsStripContent = ({ queryRef, deployedCount }: StatsStripContentProps) => {
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

  // Read/write totals are monotonic counters: the per-second rate is derived
  // from the delta between two consecutive 5s polls.
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

  return (
    <FlowRibbon
      deployedCount={deployedCount}
      metrics={{ queuedBundles, consumers, ackRate, readOperations, writeOperations, docsCount }}
    />
  );
};

interface IntegrationsStatsStripProps {
  deployedCount: number;
}

// The ingestion pipeline visualization rendered inside the Integrations hero,
// refreshed every five seconds. The refetch uses store-and-network so the
// previous values stay on screen while polling (no flicker). Users without
// the MODULES capability still get the ribbon shape with the deployed count.
const IntegrationsStatsStrip = ({ deployedCount }: IntegrationsStatsStripProps) => {
  const isConnectorReader = useGranted([MODULES]);
  const [queryRef, loadQuery] = useQueryLoader<IntegrationsStatsStripQuery>(integrationsStatsStripQuery);

  useEffect(() => {
    if (!isConnectorReader) return undefined;
    loadQuery({}, { fetchPolicy: 'store-and-network' });
    const subscription = interval$.subscribe(() => {
      loadQuery({}, { fetchPolicy: 'store-and-network' });
    });
    return () => subscription.unsubscribe();
  }, [isConnectorReader, loadQuery]);

  if (!isConnectorReader || !queryRef) {
    return <FlowRibbon deployedCount={deployedCount} metrics={EMPTY_METRICS} />;
  }

  return (
    <Suspense fallback={<FlowRibbon deployedCount={deployedCount} metrics={EMPTY_METRICS} />}>
      <StatsStripContent queryRef={queryRef} deployedCount={deployedCount} />
    </Suspense>
  );
};

export default IntegrationsStatsStrip;
