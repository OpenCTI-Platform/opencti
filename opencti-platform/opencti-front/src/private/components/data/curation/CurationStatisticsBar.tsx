import { ReactNode, Suspense } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import { useTheme } from '@mui/styles';
import Card from '@common/card/Card';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import { CURATION_HEALTH_PATH, CURATION_MERGES_PATH } from './curationUtils';
import { CurationStatisticsBarQuery } from './__generated__/CurationStatisticsBarQuery.graphql';

export const curationStatisticsBarQuery = graphql`
  query CurationStatisticsBarQuery {
    curationStatistics {
      open_count
      ambiguous_count
      active_merge_records_count
      latest_health_score
      last_scan_date
    }
  }
`;

interface StatCardProps {
  label: string;
  value: ReactNode;
  to?: string;
  compact?: boolean;
}

const StatCard = ({ label, value, to, compact = false }: StatCardProps) => {
  const theme = useTheme<Theme>();
  return (
    <Card to={to} sx={{ paddingY: 2 }}>
      <Typography color={theme.palette.text.light} variant="body2" gutterBottom>
        {label}
      </Typography>
      <div data-testid={`curation-stat-${label}`} style={{ fontSize: compact ? 16 : 32, lineHeight: compact ? 2 : 1, fontWeight: 600 }}>
        {value}
      </div>
    </Card>
  );
};

const CurationStatisticsBarComponent = () => {
  const { t_i18n, n, fldt } = useFormatter();
  const { curationStatistics } = useLazyLoadQuery<CurationStatisticsBarQuery>(curationStatisticsBarQuery, {}, { fetchPolicy: 'store-and-network' });
  return (
    <Box
      data-testid="curation-statistics"
      sx={{ display: 'grid', gridTemplateColumns: 'repeat(5, minmax(0, 1fr))', gap: 2, marginBottom: 2 }}
    >
      <StatCard label={t_i18n('Open proposals')} value={n(curationStatistics.open_count)} />
      <StatCard label={t_i18n('In the ambiguous band')} value={n(curationStatistics.ambiguous_count)} />
      <StatCard label={t_i18n('Reversible merges')} value={n(curationStatistics.active_merge_records_count)} to={CURATION_MERGES_PATH} />
      <StatCard label={t_i18n('Knowledge Health')} value={curationStatistics.latest_health_score ?? '-'} to={CURATION_HEALTH_PATH} />
      <StatCard
        label={t_i18n('Last scan')}
        value={curationStatistics.last_scan_date ? fldt(curationStatistics.last_scan_date) : t_i18n('Never')}
        compact
      />
    </Box>
  );
};

const CurationStatisticsBar = () => (
  <Suspense fallback={<Box sx={{ height: 96, marginBottom: 2 }} />}>
    <CurationStatisticsBarComponent />
  </Suspense>
);

export default CurationStatisticsBar;
