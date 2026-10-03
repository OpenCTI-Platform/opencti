import React, { Suspense } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { Chip, Text } from '@filigran/design-system';
import { Box } from '@mui/material';
import { useFormatter } from '../../../../components/i18n';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import type { GraphAnalyticsStatusQuery } from './__generated__/GraphAnalyticsStatusQuery.graphql';

const statusQuery = graphql`
  query GraphAnalyticsStatusQuery {
    graphAnalyticsStatus {
      manager_enabled
      pending_entities
      last_incremental_run
      full_pass_in_progress
      last_full_pass_completed_at
      similarity_documents
      clusters_count
      analytics_process_active
      analytics_process_last_run_at
      analytics_process_version
    }
  }
`;

const StatusComponent = ({ queryRef }: { queryRef: PreloadedQuery<GraphAnalyticsStatusQuery> }) => {
  const { t_i18n, fldt, n } = useFormatter();
  const { graphAnalyticsStatus: status } = usePreloadedQuery(statusQuery, queryRef);
  if (!status) return null;
  const engine = status.analytics_process_active
    ? `${t_i18n('Analytics process')}${status.analytics_process_version ? ` ${status.analytics_process_version}` : ''}`
    : t_i18n('Platform');
  return (
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap' }} data-testid="graph-analytics-status">
      <Chip
        label={status.manager_enabled ? t_i18n('Graph analytics enabled') : t_i18n('Graph analytics disabled')}
        severity={status.manager_enabled ? 'info' : 'medium'}
      />
      <Chip label={`${t_i18n('Clustering by')} ${engine}`} />
      <Chip label={`${n(status.clusters_count)} ${t_i18n('clusters')}`} />
      <Chip label={`${n(status.similarity_documents)} ${t_i18n('similarity links')}`} />
      {status.pending_entities > 0 && <Chip label={`${n(status.pending_entities)} ${t_i18n('entities waiting for a recompute')}`} />}
      {status.full_pass_in_progress && <Chip label={t_i18n('Full pass in progress')} severity="info" />}
      <Text variant="content-caption">
        {[
          status.last_full_pass_completed_at && `${t_i18n('Last full pass')} ${fldt(status.last_full_pass_completed_at)}`,
          status.analytics_process_last_run_at && `${t_i18n('Last analytics run')} ${fldt(status.analytics_process_last_run_at)}`,
        ].filter(Boolean).join(' - ')}
      </Text>
    </Box>
  );
};

/** Freshness of the graph analytics: who computes the clusters and when the knowledge was last analyzed. */
const GraphAnalyticsStatus = () => {
  const queryRef = useQueryLoading<GraphAnalyticsStatusQuery>(statusQuery, {});
  return queryRef ? (
    <Suspense fallback={<span />}>
      <StatusComponent queryRef={queryRef} />
    </Suspense>
  ) : null;
};

export default GraphAnalyticsStatus;
