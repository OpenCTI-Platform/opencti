import { useEffect, useState } from 'react';
import { graphql } from 'react-relay';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import { useTheme } from '@mui/styles';
import Card from '@common/card/Card';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import { fetchQuery } from '../../../../relay/environment';
import useGranted, { KNOWLEDGE } from '../../../../utils/hooks/useGranted';
import useDraftContext from '../../../../utils/hooks/useDraftContext';
import useCurationLabels, { CURATION_HEALTH_PATH } from './curationUtils';
import { KnowledgeHealthBadgeQuery$data } from './__generated__/KnowledgeHealthBadgeQuery.graphql';

const knowledgeHealthBadgeQuery = graphql`
  query KnowledgeHealthBadgeQuery {
    knowledgeHealth {
      id
      health_score
      score_trend
      snapshot_date
    }
    curationStatistics {
      open_count
    }
  }
`;

type BadgeData = { score: number; trend: number | null; openCount: number };

/**
 * Home badge of the Knowledge Health score, linking to its dashboard. Shown once a snapshot exists; a failed
 * lookup never affects the home page.
 */
const KnowledgeHealthBadge = () => {
  const theme = useTheme<Theme>();
  const { t_i18n, n } = useFormatter();
  const { healthColor } = useCurationLabels();
  const isGrantedToKnowledge = useGranted([KNOWLEDGE]);
  const draftContext = useDraftContext();
  const [badge, setBadge] = useState<BadgeData | null>(null);

  useEffect(() => {
    if (!isGrantedToKnowledge || draftContext) return undefined;
    let active = true;
    fetchQuery(knowledgeHealthBadgeQuery, {})
      .toPromise()
      .then((data) => {
        const result = data as KnowledgeHealthBadgeQuery$data | undefined;
        if (!active || !result?.knowledgeHealth) return;
        setBadge({
          score: result.knowledgeHealth.health_score,
          trend: result.knowledgeHealth.score_trend ?? null,
          openCount: result.curationStatistics.open_count,
        });
      })
      .catch(() => {
        if (active) setBadge(null);
      });
    return () => {
      active = false;
    };
  }, [isGrantedToKnowledge, draftContext]);

  if (!badge) return null;
  const trend = badge.trend === null ? '' : ` (${badge.trend >= 0 ? '+' : ''}${badge.trend})`;
  return (
    <Box sx={{ marginBottom: 2 }} data-testid="knowledge-health-badge">
      <Card to={CURATION_HEALTH_PATH} padding="small">
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, flexWrap: 'wrap' }}>
          <Typography variant="body2" color={theme.palette.text.light}>{t_i18n('Knowledge Health')}</Typography>
          <Typography variant="h3" sx={{ margin: 0, color: healthColor(badge.score) }}>
            {badge.score}/100{trend}
          </Typography>
          <Typography variant="body2" color={theme.palette.text.light}>
            {n(badge.openCount)} {t_i18n('open curation proposals')}
          </Typography>
        </Box>
      </Card>
    </Box>
  );
};

export default KnowledgeHealthBadge;
