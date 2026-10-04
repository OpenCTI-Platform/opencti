import React, { ReactNode, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { Chip, Paper, Text } from '@filigran/design-system';
import { Box, Skeleton } from '@mui/material';
import Button from '@common/button/Button';
import { useFormatter } from '../../../../components/i18n';
import GraphRelativeTime from '../../common/graph_analytics/GraphRelativeTime';
import { GRAPH_ANALYTICS_STATE_CHIPS, resolveGraphAnalyticsState } from '../../common/graph_analytics/graphAnalyticsUtils';
import GraphAnalyticsPendingDialog from './GraphAnalyticsPendingDialog';
import type { GraphAnalyticsStatusQuery } from './__generated__/GraphAnalyticsStatusQuery.graphql';

export const graphAnalyticsStatusQuery = graphql`
  query GraphAnalyticsStatusQuery {
    graphAnalyticsStatus {
      manager_enabled
      pending_entities
      full_pass_in_progress
      last_full_pass_completed_at
      last_full_pass_ended_at
      next_full_pass_at
      similarity_documents
      clusters_count
      analytics_process_active
      analytics_process_last_run_at
      analytics_process_version
    }
  }
`;

interface GraphAnalyticsKpiProps {
  label: string;
  value: string;
  action?: ReactNode;
  testId: string;
}

const GraphAnalyticsKpi = ({ label, value, action, testId }: GraphAnalyticsKpiProps) => (
  <Paper elevation={1} padding={16} data-testid={testId}>
    <Box sx={{ display: 'flex', alignItems: 'flex-end', justifyContent: 'space-between', gap: 1 }}>
      <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.5, minWidth: 0 }}>
        <Text variant="content-caption">{label}</Text>
        <Text variant="title-lg" as="span">{value}</Text>
      </Box>
      {action}
    </Box>
  </Paper>
);

const KPI_GRID_SX = { display: 'grid', gridTemplateColumns: { xs: '1fr', md: 'repeat(3, minmax(0, 1fr))' }, gap: 2 };

/** Status header of the graph analytics: their state, the headline counts, and who computes the clusters in the details. */
const GraphAnalyticsStatus = ({ queryRef }: { queryRef: PreloadedQuery<GraphAnalyticsStatusQuery> }) => {
  const { t_i18n, n } = useFormatter();
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [pendingOpen, setPendingOpen] = useState(false);
  const { graphAnalyticsStatus: status } = usePreloadedQuery(graphAnalyticsStatusQuery, queryRef);
  if (!status) return null;
  const state = resolveGraphAnalyticsState(status);
  const chip = GRAPH_ANALYTICS_STATE_CHIPS[state];
  let sentence: ReactNode;
  if (state === 'disabled') {
    sentence = t_i18n('Graph analytics are disabled on this platform.');
  } else if (state === 'analysing') {
    sentence = status.pending_entities > 0
      ? t_i18n('{count, plural, one {# entity} other {# entities}} left', { values: { count: status.pending_entities } })
      : t_i18n('Full pass of the knowledge graph in progress');
  } else if (state === 'not_analysed') {
    sentence = t_i18n('The first full pass of the knowledge graph starts in the next minutes.');
  } else if (status.last_full_pass_completed_at) {
    sentence = <GraphRelativeTime date={status.last_full_pass_completed_at} template="Last full pass {time}" />;
  } else if (status.last_full_pass_ended_at) {
    sentence = <GraphRelativeTime date={status.last_full_pass_ended_at} template="Last pass {time} stopped at its entity limit, the next one continues where it stopped" />;
  } else {
    sentence = <GraphRelativeTime date={status.analytics_process_last_run_at as string} template="Last analytics run {time}" />;
  }
  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.5 }} data-testid="graph-analytics-status">
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap' }}>
        <Chip label={t_i18n(chip.label)} severity={chip.severity} />
        <Text variant="content-base" as="span" aria-live="polite">{sentence}</Text>
        <Box sx={{ flex: 1 }} />
        <Button
          variant="tertiary"
          size="small"
          aria-expanded={detailsOpen}
          aria-controls="graph-analytics-status-details"
          onClick={() => setDetailsOpen(!detailsOpen)}
        >
          {detailsOpen ? t_i18n('Hide details') : t_i18n('Details')}
        </Button>
      </Box>
      {detailsOpen && (
        <Box id="graph-analytics-status-details" sx={{ display: 'flex', flexDirection: 'column', gap: 0.5 }} data-testid="graph-analytics-status-details">
          <Text variant="content-caption">
            {status.analytics_process_active
              ? t_i18n('Clusters are computed by the analytics process {version}', { values: { version: status.analytics_process_version ?? '' } })
              : t_i18n('Clusters are computed by the platform')}
          </Text>
          {status.analytics_process_last_run_at && (
            <Text variant="content-caption">
              <GraphRelativeTime date={status.analytics_process_last_run_at} template="Last analytics run {time}" />
            </Text>
          )}
        </Box>
      )}
      <Box sx={KPI_GRID_SX}>
        <GraphAnalyticsKpi testId="graph-analytics-kpi-clusters" label={t_i18n('Clusters')} value={n(status.clusters_count)} />
        <GraphAnalyticsKpi testId="graph-analytics-kpi-similarity" label={t_i18n('Similarity links')} value={n(status.similarity_documents)} />
        <GraphAnalyticsKpi
          testId="graph-analytics-kpi-pending"
          label={t_i18n('Entities waiting for analysis')}
          value={n(status.pending_entities)}
          action={status.pending_entities > 0 && (
            <Button variant="secondary" size="small" onClick={() => setPendingOpen(true)} data-testid="graph-analytics-pending-open">
              {t_i18n('Show the entities')}
            </Button>
          )}
        />
      </Box>
      {pendingOpen && <GraphAnalyticsPendingDialog pendingCount={status.pending_entities} onClose={() => setPendingOpen(false)} />}
    </Box>
  );
};

export const GraphAnalyticsStatusSkeleton = () => (
  <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.5 }}>
    <Skeleton variant="rounded" height={28} width="40%" />
    <Box sx={KPI_GRID_SX}>
      {[0, 1, 2].map((index) => <Skeleton key={index} variant="rounded" height={84} />)}
    </Box>
  </Box>
);

export default GraphAnalyticsStatus;
