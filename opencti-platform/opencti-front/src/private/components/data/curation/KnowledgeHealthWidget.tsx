import React, { ReactNode, useEffect, useRef, useState } from 'react';
import { graphql } from 'react-relay';
import Box from '@mui/material/Box';
import { useDashboardRefreshToken, useDashboardSetQueryPending } from '../../../../components/dashboard/DashboardRefreshContext';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetMultiLines from '../../../../components/dashboard/WidgetMultiLines';
import WidgetHorizontalBars from '../../../../components/dashboard/WidgetHorizontalBars';
import { useFormatter } from '../../../../components/i18n';
import { fetchQuery } from '../../../../relay/environment';
import CurationSkeleton from './CurationSkeleton';
import KnowledgeHealthScore from './KnowledgeHealthScore';
import useCurationLabels from './curationUtils';
import { KnowledgeHealthWidgetQuery$data } from './__generated__/KnowledgeHealthWidgetQuery.graphql';

export const KNOWLEDGE_HEALTH_WIDGET_TYPES = ['knowledge-health-score', 'knowledge-health-trend', 'curation-open-proposals'] as const;
export type KnowledgeHealthWidgetType = typeof KNOWLEDGE_HEALTH_WIDGET_TYPES[number];

const TREND_SNAPSHOTS = 30;

const knowledgeHealthWidgetQuery = graphql`
  query KnowledgeHealthWidgetQuery($snapshots: Int!) {
    knowledgeHealth {
      id
      health_score
      score_trend
    }
    knowledgeHealthSnapshots(first: $snapshots, orderBy: snapshot_date, orderMode: desc) {
      edges {
        node {
          id
          snapshot_date
          health_score
        }
      }
    }
    curationStatistics {
      open_count
      open_by_kind {
        key
        count
      }
    }
  }
`;

interface KnowledgeHealthWidgetProps {
  variant: KnowledgeHealthWidgetType;
  title?: string | null;
  popover?: ReactNode;
}

/**
 * Dashboard widgets of the Knowledge Health score, read from the curation snapshots. They need no data selection: the
 * score covers every curated entity the platform holds. A failed read (no access, a public dashboard) shows no data.
 * A manual or automatic dashboard refresh reads them again, the current figures staying on screen until it answers.
 */
const KnowledgeHealthWidget = ({ variant, title, popover }: KnowledgeHealthWidgetProps) => {
  const { t_i18n } = useFormatter();
  const labels = useCurationLabels();
  const [state, setState] = useState<{ loading: boolean; data: KnowledgeHealthWidgetQuery$data | null }>({ loading: true, data: null });
  const refreshToken = useDashboardRefreshToken();
  const setQueryPending = useDashboardSetQueryPending();
  const queryIdRef = useRef(`knowledge-health-widget-${Math.random().toString(36).slice(2)}`);

  useEffect(() => {
    let active = true;
    const queryId = queryIdRef.current;
    setQueryPending(queryId, true);
    fetchQuery(knowledgeHealthWidgetQuery, { snapshots: TREND_SNAPSHOTS })
      .toPromise()
      .then((data) => {
        if (active) setState({ loading: false, data: (data as KnowledgeHealthWidgetQuery$data | undefined) ?? null });
      })
      .catch(() => {
        if (active) setState({ loading: false, data: null });
      })
      .finally(() => setQueryPending(queryId, false));
    return () => {
      active = false;
      setQueryPending(queryId, false);
    };
  }, [refreshToken, setQueryPending]);

  const defaultTitles: Record<KnowledgeHealthWidgetType, string> = {
    'knowledge-health-score': t_i18n('Knowledge health score'),
    'knowledge-health-trend': t_i18n('Knowledge health trend'),
    'curation-open-proposals': t_i18n('Open curation proposals by kind'),
  };

  const renderContent = () => {
    if (state.loading) {
      return <CurationSkeleton blocks={[160]} />;
    }
    const { data } = state;
    if (!data) {
      return <WidgetNoData message={t_i18n('Knowledge health is not available here: it needs the capability to access knowledge.')} />;
    }
    const noSnapshot = t_i18n('No Knowledge health snapshot yet: the curation manager computes one once a day.');
    if (variant === 'knowledge-health-score') {
      if (!data.knowledgeHealth) return <WidgetNoData message={noSnapshot} />;
      const { health_score: score, score_trend: trend } = data.knowledgeHealth;
      return (
        <Box sx={{ textAlign: 'center' }} data-testid="knowledge-health-widget-score">
          <KnowledgeHealthScore score={score} height={180} />
          {trend !== null && trend !== undefined && (
            <Box component="span" sx={{ color: labels.trendColor(trend) }}>
              {t_i18n('{trend} since the previous snapshot', { values: { trend: `${trend >= 0 ? '+' : ''}${trend}` } })}
            </Box>
          )}
        </Box>
      );
    }
    if (variant === 'knowledge-health-trend') {
      const points = (data.knowledgeHealthSnapshots?.edges ?? [])
        .map((edge) => edge?.node)
        .filter((node): node is NonNullable<typeof node> => !!node)
        .map((node) => ({ x: new Date(node.snapshot_date).getTime(), y: node.health_score }))
        .sort((left, right) => left.x - right.x);
      if (points.length === 0) return <WidgetNoData message={noSnapshot} />;
      return <WidgetMultiLines series={[{ name: t_i18n('Knowledge health score'), data: points }]} interval="day" hasLegend={false} />;
    }
    const entries = [...(data.curationStatistics?.open_by_kind ?? [])]
      .filter((entry) => entry.count > 0)
      .sort((left, right) => right.count - left.count);
    if (entries.length === 0) return <WidgetNoData message={t_i18n('No open curation proposal: the detectors found nothing to review.')} />;
    return (
      <WidgetHorizontalBars
        series={[{ name: t_i18n('Open curation proposals'), data: entries.map((entry) => entry.count) }]}
        categories={entries.map((entry) => labels.kind(entry.key))}
        distributed={true}
      />
    );
  };

  return (
    <WidgetContainer title={title || defaultTitles[variant]} action={popover}>
      {renderContent()}
    </WidgetContainer>
  );
};

export default KnowledgeHealthWidget;
