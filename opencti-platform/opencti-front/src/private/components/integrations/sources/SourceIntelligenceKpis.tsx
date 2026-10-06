import React from 'react';
import { Link } from 'react-router';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { Box, Skeleton, Stack, Typography } from '@mui/material';
import { useTheme } from '@mui/material/styles';
import { useFormatter } from '../../../../components/i18n';
import { paperBg, paperBorder } from '../paperSurface';
import { SourceIntelligenceKpisQuery } from './__generated__/SourceIntelligenceKpisQuery.graphql';

export const sourceIntelligenceKpisQuery = graphql`
  query SourceIntelligenceKpisQuery($quarantinedFilters: FilterGroup, $enterprise: Boolean!) {
    sources(first: 1) {
      pageInfo {
        globalCount
      }
    }
    quarantined: sources(first: 1, filters: $quarantinedFilters) {
      pageInfo {
        globalCount
      }
    }
    sourceRecommendations(first: 1, status: [proposed]) @include(if: $enterprise) {
      pageInfo {
        globalCount
      }
    }
    collectionGaps(first: 1, onlyGaps: true) @include(if: $enterprise) {
      pageInfo {
        globalCount
      }
    }
  }
`;

export const QUARANTINED_SOURCES_FILTERS = {
  mode: 'and',
  filters: [{ key: ['quarantined'], values: ['true'], operator: 'eq', mode: 'or' }],
  filterGroups: [],
};

const LEADERBOARD_PATH = '/dashboard/integrations/sources';

interface KpiProps {
  label: string;
  value: number;
  to: string;
  testId: string;
}

const Kpi = ({ label, value, to, testId }: KpiProps) => {
  const theme = useTheme();
  const { n } = useFormatter();
  return (
    <Box
      component={Link}
      to={to}
      data-testid={testId}
      sx={{
        flex: 1,
        minWidth: 160,
        display: 'block',
        padding: 2,
        borderRadius: 1,
        border: `1px solid ${paperBorder(theme)}`,
        backgroundColor: paperBg(theme),
        color: 'text.primary',
        textDecoration: 'none',
        '&:hover': { borderColor: 'primary.main' },
        '&:focus-visible': { outline: `2px solid ${theme.palette.primary.main}`, outlineOffset: 2 },
      }}
    >
      <Typography variant="body2" sx={{ color: 'text.secondary' }}>{label}</Typography>
      <Typography variant="h2" component="div" sx={{ margin: 0 }}>{n(value)}</Typography>
    </Box>
  );
};

export const SourceIntelligenceKpisSkeleton = () => (
  <Stack direction="row" gap={2} flexWrap="wrap" aria-hidden>
    {[0, 1, 2, 3].map((index) => (
      <Skeleton key={index} variant="rounded" height={72} sx={{ flex: 1, minWidth: 160 }} />
    ))}
  </Stack>
);

/**
 * Counters that read the state of the collection for the reader; each one opens the items it counts.
 */
const SourceIntelligenceKpis = ({ queryRef }: { queryRef: PreloadedQuery<SourceIntelligenceKpisQuery> }) => {
  const { t_i18n } = useFormatter();
  const data = usePreloadedQuery(sourceIntelligenceKpisQuery, queryRef);
  const quarantinedLink = `${LEADERBOARD_PATH}?filters=${encodeURIComponent(JSON.stringify(QUARANTINED_SOURCES_FILTERS))}`;
  return (
    <Stack direction="row" gap={2} flexWrap="wrap" component="nav" aria-label={t_i18n('Source intelligence summary')} data-testid="source-intelligence-kpis">
      <Kpi label={t_i18n('Sources')} value={data.sources?.pageInfo.globalCount ?? 0} to={LEADERBOARD_PATH} testId="source-intelligence-kpi-sources" />
      <Kpi label={t_i18n('Quarantined sources')} value={data.quarantined?.pageInfo.globalCount ?? 0} to={quarantinedLink} testId="source-intelligence-kpi-quarantined" />
      {data.sourceRecommendations && (
        <Kpi
          label={t_i18n('Recommendations to review')}
          value={data.sourceRecommendations.pageInfo.globalCount}
          to={`${LEADERBOARD_PATH}/recommendations`}
          testId="source-intelligence-kpi-recommendations"
        />
      )}
      {data.collectionGaps && (
        <Kpi
          label={t_i18n('Collection gaps')}
          value={data.collectionGaps.pageInfo.globalCount}
          to={`${LEADERBOARD_PATH}/gaps`}
          testId="source-intelligence-kpi-gaps"
        />
      )}
    </Stack>
  );
};

export default SourceIntelligenceKpis;
