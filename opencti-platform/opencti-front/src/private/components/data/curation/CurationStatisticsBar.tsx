import { ReactNode } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { Text, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import { useTheme } from '@mui/styles';
import Card from '@common/card/Card';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import CurationSkeleton from './CurationSkeleton';
import { CURATION_HEALTH_PATH, CURATION_MERGES_PATH } from './curationUtils';
import { CurationStatisticsBarQuery, CurationStatisticsBarQuery$data } from './__generated__/CurationStatisticsBarQuery.graphql';

export const curationStatisticsBarQuery = graphql`
  query CurationStatisticsBarQuery {
    curationStatistics {
      open_count
      ambiguous_count
      decided_by_status {
        key
        count
      }
      active_merge_records_count
      latest_health_score
      last_scan_date
      curation_enabled
      next_scan_date
    }
  }
`;

export type CurationStatistics = CurationStatisticsBarQuery$data['curationStatistics'];

/** The Inbox filters the counters of the strip apply. */
export type CurationInboxFilter = 'open' | 'needs_decision';

/** No proposal was ever raised: the Inbox shows its first-use state instead of an empty table. */
export const hasNoProposalYet = (statistics: CurationStatistics) => {
  return statistics.open_count === 0 && statistics.decided_by_status.every((entry) => entry.count === 0);
};

export const useCurationStatistics = (fetchKey = 0) => {
  const { curationStatistics } = useLazyLoadQuery<CurationStatisticsBarQuery>(
    curationStatisticsBarQuery,
    {},
    { fetchPolicy: 'store-and-network', fetchKey },
  );
  return curationStatistics;
};

interface StatCardProps {
  label: string;
  value: ReactNode;
  testId: string;
  to?: string;
  onClick?: () => void;
  active?: boolean;
  compact?: boolean;
}

const StatCard = ({ label, value, testId, to, onClick, active = false, compact = false }: StatCardProps) => {
  const theme = useTheme<Theme>();
  return (
    <Card
      to={to}
      onClick={onClick}
      sx={{ paddingY: 2, ...(active ? { outline: `1px solid ${theme.palette.primary.main}` } : {}) }}
    >
      <Typography color={theme.palette.text.light} variant="body2" gutterBottom>
        {label}
      </Typography>
      <Text as="div" variant={compact ? 'title-sm' : 'title-2xl'} data-testid={`curation-stat-${testId}`} data-active={active}>
        {value}
      </Text>
    </Card>
  );
};

interface CurationStatisticsBarProps {
  statistics: CurationStatistics;
  activeFilter: CurationInboxFilter | null;
  onFilter: (filter: CurationInboxFilter) => void;
}

const CurationStatisticsBar = ({ statistics, activeFilter, onFilter }: CurationStatisticsBarProps) => {
  const { t_i18n, n, fldt, rd } = useFormatter();
  const score = statistics.latest_health_score;
  const hasScore = score !== null && score !== undefined;
  return (
    <Box
      data-testid="curation-statistics"
      sx={{ display: 'grid', gridTemplateColumns: 'repeat(5, minmax(0, 1fr))', gap: 2, marginBottom: 2 }}
    >
      <StatCard
        testId="open"
        label={t_i18n('Open proposals')}
        value={n(statistics.open_count)}
        onClick={() => onFilter('open')}
        active={activeFilter === 'open'}
      />
      <StatCard
        testId="needs-decision"
        label={t_i18n('Needs your decision')}
        value={n(statistics.ambiguous_count)}
        onClick={() => onFilter('needs_decision')}
        active={activeFilter === 'needs_decision'}
      />
      <StatCard testId="merges" label={t_i18n('Reversible merges')} value={n(statistics.active_merge_records_count)} to={CURATION_MERGES_PATH} />
      <StatCard
        testId="health"
        label={t_i18n('Knowledge health')}
        value={hasScore ? t_i18n('{score} / 100', { values: { score } }) : t_i18n('Not computed yet')}
        to={CURATION_HEALTH_PATH}
        compact={!hasScore}
      />
      <StatCard
        testId="last-scan"
        label={t_i18n('Last scan')}
        value={statistics.last_scan_date ? (
          <Tooltip>
            <TooltipTrigger asChild>
              <span>{rd(statistics.last_scan_date)}</span>
            </TooltipTrigger>
            <TooltipContent>{fldt(statistics.last_scan_date)}</TooltipContent>
          </Tooltip>
        ) : t_i18n('Never')}
        compact
      />
    </Box>
  );
};

export const CurationStatisticsBarSkeleton = () => <CurationSkeleton blocks={[96, 480]} />;

export default CurationStatisticsBar;
