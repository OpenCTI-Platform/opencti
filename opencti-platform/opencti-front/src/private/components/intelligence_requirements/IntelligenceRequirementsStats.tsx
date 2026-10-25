import React from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { Paper, Text } from '@filigran/design-system';
import Box from '@mui/material/Box';
import { useTheme } from '@mui/material/styles';
import type { Theme } from '../../../components/Theme';
import { useFormatter } from '../../../components/i18n';
import WidgetDonut from '../../../components/dashboard/WidgetDonut';
import WidgetNoData from '../../../components/dashboard/WidgetNoData';
import type { IntelligenceRequirementsStatsQuery } from './__generated__/IntelligenceRequirementsStatsQuery.graphql';

// Synthesis of the requirements, above the list: total, priority, status, entities and inbox.

const statsQuery = graphql`
  query IntelligenceRequirementsStatsQuery {
    intelligenceRequirements(first: 500) {
      pageInfo { globalCount }
      edges {
        node {
          id
          ir_priority
          ir_status
          ir_entities_count
          ir_inbox_open_count
        }
      }
    }
  }
`;

const PRIORITIES = ['critical', 'high', 'medium', 'low'];
const STATUSES = ['active', 'paused'];

const Tile = ({ title, children }: { title: string; children: React.ReactNode }) => (
  <Paper padding={16} style={{ height: '100%' }}>
    <Text as="div" variant="content-caption" style={{ opacity: 0.8, marginBottom: 8 }}>{title}</Text>
    {children}
  </Paper>
);

const Figure = ({ value, detail }: { value: number; detail?: string }) => (
  <>
    <Text as="div" variant="title-xl">{String(value)}</Text>
    {detail && <Text as="div" variant="content-caption" style={{ opacity: 0.7 }}>{detail}</Text>}
  </>
);

const Donut = ({ data, groupBy }: { data: { label: string; value: number; entity: { color: string } }[]; groupBy: string }) => (
  <Box sx={{ height: 140 }}>
    {data.some((d) => d.value > 0) ? <WidgetDonut data={data} groupBy={groupBy} /> : <WidgetNoData />}
  </Box>
);

const IntelligenceRequirementsStats = () => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  // Donut colours carry the meaning of the value (the widget reads entity.color)
  const priorityColors: Record<string, string> = {
    critical: theme.palette.error.main,
    high: theme.palette.warning.main,
    medium: theme.palette.info.main,
    low: theme.palette.success.main,
  };
  const statusColors: Record<string, string> = { active: theme.palette.success.main, paused: theme.palette.grey[500] };
  const capitalize = (value: string) => value.charAt(0).toUpperCase() + value.slice(1);
  const data = useLazyLoadQuery<IntelligenceRequirementsStatsQuery>(statsQuery, {}, { fetchPolicy: 'store-and-network' });
  const requirements = (data.intelligenceRequirements?.edges ?? []).map((e) => e.node);
  const count = (key: 'ir_priority' | 'ir_status', value: string) => requirements.filter((r) => r[key] === value).length;
  const active = count('ir_status', 'active');
  const entities = requirements.reduce((sum, r) => sum + r.ir_entities_count, 0);
  const inbox = requirements.reduce((sum, r) => sum + r.ir_inbox_open_count, 0);
  return (
    <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1.4fr 1.4fr 1fr 1fr', gap: 2, mb: 2 }}>
      <Tile title={t_i18n('Total PIRs')}>
        <Figure value={data.intelligenceRequirements?.pageInfo.globalCount ?? requirements.length} detail={`${active} ${t_i18n('active')} · ${requirements.length - active} ${t_i18n('paused')}`} />
      </Tile>
      <Tile title={t_i18n('PIR priority')}>
        <Donut groupBy="ir_priority" data={PRIORITIES.map((p) => ({ label: t_i18n(capitalize(p)), value: count('ir_priority', p), entity: { color: priorityColors[p] } }))} />
      </Tile>
      <Tile title={t_i18n('PIR status')}>
        <Donut groupBy="ir_status" data={STATUSES.map((s) => ({ label: t_i18n(s === 'active' ? 'Active' : 'Paused'), value: count('ir_status', s), entity: { color: statusColors[s] } }))} />
      </Tile>
      <Tile title={t_i18n('Entities in the PIRs')}>
        <Figure value={entities} detail={t_i18n('in or accepted, all PIRs')} />
      </Tile>
      <Tile title={t_i18n('Inbox · to review')}>
        <Figure value={inbox} detail={t_i18n('open items, all PIRs')} />
      </Tile>
    </Box>
  );
};

export default IntelligenceRequirementsStats;
