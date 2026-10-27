import React from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import type { ApexOptions } from 'apexcharts';
import { useTheme } from '@mui/material/styles';
import { Chip, Text } from '@filigran/design-system';
import Box from '@mui/material/Box';
import Chart from '@components/common/charts/Chart';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import type { IrScoreHistoryQuery } from './__generated__/IrScoreHistoryQuery.graphql';

// History of an entity of the requirement: its score over time (step chart, score thresholds, periods where it did not
// meet the conditions of the scope), and the events that changed it. Without relevance rules, the timeline only.

const historyQuery = graphql`
  query IrScoreHistoryQuery($id: ID!, $irId: ID!) {
    intelligenceRequirementMatch(id: $id) {
      id
      match_history { at score eligible status kind trigger changes }
    }
    intelligenceRequirement(id: $irId) {
      id
      ir_thresholds
      ir_relevance_rules { id enabled }
    }
  }
`;

type Point = NonNullable<IrScoreHistoryQuery['response']['intelligenceRequirementMatch']>['match_history'][number];

const KIND_LABEL: Record<string, string> = { entry: 'Entered', fact: 'New fact', config: 'Configuration', decision: 'Decision' };
const MAX_EVENTS = 8;

const escapeHtml = (value: string) => value.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] as string);

const IrScoreHistory = ({ matchId, irId }: { matchId: string; irId: string }) => {
  const theme = useTheme<Theme>();
  const { t_i18n, fldt } = useFormatter();
  const data = useLazyLoadQuery<IrScoreHistoryQuery>(historyQuery, { id: matchId, irId }, { fetchPolicy: 'network-only' });
  const points = [...(data.intelligenceRequirementMatch?.match_history ?? [])].sort((a, b) => a.at.localeCompare(b.at));
  const thresholds = data.intelligenceRequirement?.ir_thresholds ?? [];
  const scored = (data.intelligenceRequirement?.ir_relevance_rules ?? []).some((r) => r.enabled);
  if (points.length === 0) {
    return <Text as="div" variant="content-caption" style={{ opacity: 0.7 }}>{t_i18n('No history yet: it starts at the next change of this entity.')}</Text>;
  }
  const kindColor: Record<string, string | undefined> = {
    entry: theme.palette.primary.main,
    fact: theme.palette.primary.main,
    config: theme.palette.warn.main,
    decision: theme.palette.success.main,
  };
  const time = (p: Point) => new Date(p.at).getTime();
  const now = Date.now();
  // Step chart: the score holds until the next change, then up to now; not eligible = 0
  const series = [{ name: t_i18n('Score'), data: [...points.map((p) => ({ x: time(p), y: p.eligible ? p.score : 0 })), { x: now, y: points[points.length - 1].eligible ? points[points.length - 1].score : 0 }] }];
  const notEligible = points
    .map((p, i) => ({ p, until: i + 1 < points.length ? time(points[i + 1]) : now }))
    .filter(({ p }) => !p.eligible)
    .map(({ p, until }) => ({ x: time(p), x2: until, fillColor: theme.palette.text.disabled, opacity: 0.15, label: { text: t_i18n('not eligible'), style: { color: theme.palette.text.secondary, background: 'transparent' } } }));
  const options: ApexOptions = {
    chart: { type: 'line', toolbar: { show: false }, zoom: { enabled: false }, animations: { enabled: false }, background: 'transparent' },
    theme: { mode: theme.palette.mode },
    stroke: { curve: 'stepline', width: 2 },
    colors: [theme.palette.primary.main],
    grid: { borderColor: theme.palette.divider },
    xaxis: { type: 'datetime', labels: { style: { colors: theme.palette.text.secondary } } },
    yaxis: { min: 0, max: 100, tickAmount: 4, labels: { style: { colors: theme.palette.text.secondary } } },
    markers: {
      size: 0,
      discrete: points.map((p, i) => ({
        seriesIndex: 0,
        dataPointIndex: i,
        size: 5,
        fillColor: kindColor[p.kind] ?? theme.palette.primary.main,
        strokeColor: theme.palette.background.paper,
      })),
    },
    annotations: {
      yaxis: thresholds.map((t) => ({
        y: t,
        borderColor: theme.palette.text.secondary,
        strokeDashArray: 4,
        label: { text: String(t), style: { color: theme.palette.text.primary, background: theme.palette.background.paper } },
      })),
      xaxis: notEligible,
    },
    tooltip: {
      theme: theme.palette.mode,
      custom: ({ dataPointIndex }: { dataPointIndex: number }) => {
        const p = points[Math.min(dataPointIndex, points.length - 1)];
        const lines = [
          `<b>${escapeHtml(fldt(p.at))}</b>`,
          `${escapeHtml(t_i18n('Score'))}: ${p.eligible ? p.score : '—'}${p.eligible ? '' : ` (${escapeHtml(t_i18n('not eligible'))})`}`,
          p.trigger ? escapeHtml(p.trigger) : '',
          ...p.changes.map((c) => `• ${escapeHtml(c)}`),
        ].filter(Boolean);
        return `<div style="padding:8px 10px;font-size:12px;line-height:1.5">${lines.join('<br/>')}</div>`;
      },
    },
    legend: { show: false },
  };
  const events = [...points].reverse().slice(0, MAX_EVENTS);
  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.5 }}>
      {scored && <Chart type="line" options={options} series={series} width="100%" height={200} />}
      <Box>
        {events.map((p, i) => (
          <Box key={`${p.at}-${i}`} sx={{ display: 'grid', gridTemplateColumns: '140px 1fr 48px', gap: 1, py: 0.75, borderBottom: '1px solid', borderColor: 'divider' }}>
            <Text as="span" variant="content-caption" style={{ opacity: 0.8 }}>{fldt(p.at)}</Text>
            <Box sx={{ minWidth: 0 }}>
              <Box sx={{ display: 'flex', gap: 1, alignItems: 'center', flexWrap: 'wrap' }}>
                <Chip label={t_i18n(KIND_LABEL[p.kind] ?? p.kind)} size="sm" />
                {!p.eligible && <Chip label={t_i18n('Not eligible')} severity="critical" size="sm" />}
                {p.trigger && <Text as="span" variant="content-caption">{p.trigger}</Text>}
              </Box>
              {p.changes.length > 0 && <Text as="div" variant="content-caption" style={{ opacity: 0.8 }}>{p.changes.join(' · ')}</Text>}
            </Box>
            <Text as="span" variant="content-compact-bold" style={{ textAlign: 'right' }}>{scored && p.eligible ? p.score : '—'}</Text>
          </Box>
        ))}
        {points.length > MAX_EVENTS && (
          <Text as="div" variant="content-caption" style={{ opacity: 0.7, marginTop: 4 }}>{`${points.length - MAX_EVENTS} ${t_i18n('earlier changes')}`}</Text>
        )}
      </Box>
    </Box>
  );
};

export default IrScoreHistory;
