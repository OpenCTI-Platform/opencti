import React, { ReactNode, startTransition, useMemo, useState } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { useSearchParams } from 'react-router';
import { Paper, Text } from '@filigran/design-system';
import Box from '@mui/material/Box';
import Button from '@common/button/Button';
import { useFormatter } from '../../../../components/i18n';
import { IrSelect } from '../configuration/IrFields';
import IrMatchDrawer, { type IrMatchData } from './IrMatchDrawer';
import { buildHighlights, dailyBuckets, type Highlight, timelineEvents, type TimelineEvent } from './irTimelineEvents';
import IrTimelineAxis from './IrTimelineAxis';
import { HighlightPill, ScoreMove } from './IrTimelineParts';
import type { IrTimelineQuery } from './__generated__/IrTimelineQuery.graphql';

// Timeline of a requirement, read from the dated history of each entity:
// - a time axis, one lane per kind of event, to see the rhythm (waves of entries, days when scores move);
// - below it, the selected day (or the whole period) told in a few cards, what deserves attention first.

const timelineQuery = graphql`
  query IrTimelineQuery($id: ID!) {
    intelligenceRequirement(id: $id) {
      id
      ir_thresholds
      ir_scope_criteria { id name kind mode from_group_ids from_in_requirement }
    }
    intelligenceRequirementMatches(id: $id, first: 1000, statuses: [auto, accepted, proposed, rejected, removed], orderBy: match_score, orderMode: desc) {
      edges {
        node {
          id
          match_status
          match_score
          match_excluded
          match_entity_type
          match_entity_id
          match_entity_name
          match_criteria_ids
          match_last_fact_at
          entity { ... on StixCoreObject { representative { main } } }
          match_history { at score eligible status kind trigger changes }
          match_explanations {
            criterion_id
            kind
            anchor_id
            relationship_type
            direction
            keyword
            field
            anchor { representative { main } }
            container { representative { main } }
          }
          match_score_breakdown { name points hit reason kind criterion_id }
        }
      }
    }
  }
`;

const PERIODS = [7, 30, 90, 0]; // days, 0 = everything
const SHOWN_IN_CARD = 40;
const DAY = 24 * 3600 * 1000;
const isoDay = (time: number) => new Date(time).toISOString().slice(0, 10);

const IrTimeline = ({ irId }: { irId: string }) => {
  const { t_i18n, fld, fsd } = useFormatter();
  const [fetchKey, setFetchKey] = useState(0);
  const data = useLazyLoadQuery<IrTimelineQuery>(timelineQuery, { id: irId }, { fetchPolicy: 'network-only', fetchKey });
  const criteria = data.intelligenceRequirement?.ir_scope_criteria ?? [];
  const thresholds = data.intelligenceRequirement?.ir_thresholds ?? [];
  const topThreshold = Math.max(...thresholds, 0);
  const matches = useMemo(() => (data.intelligenceRequirementMatches?.edges ?? []).map((e) => e.node), [data]);
  const events = useMemo(() => timelineEvents(matches, thresholds), [matches, thresholds]);

  // Opened on a day (from the preview of the Overview): the period covers that day
  const [searchParams] = useSearchParams();
  const dayParam = /^\d{4}-\d{2}-\d{2}$/.test(searchParams.get('day') ?? '') ? searchParams.get('day') : null;
  const daysAgo = dayParam ? Math.ceil((Date.now() - new Date(`${dayParam}T00:00:00Z`).getTime()) / DAY) : 0;
  const [period, setPeriod] = useState(() => PERIODS.find((p) => p > daysAgo) ?? 0);
  const [selectedDay, setSelectedDay] = useState<string | null>(dayParam);
  const [expanded, setExpanded] = useState<string[]>([]);
  const [selected, setSelected] = useState<string | null>(null);

  // The axis runs from the start of the period (or the first event) to today
  const today = isoDay(Date.now());
  const since = period > 0 ? isoDay(Date.now() - (period - 1) * DAY) : null;
  const firstEvent = events.reduce((min, e) => (e.at < min ? e.at : min), today).slice(0, 10);
  const start = since ?? firstEvent;
  const buckets = useMemo(() => dailyBuckets(events, since), [events, since]);
  const range = selectedDay
    ? { from: selectedDay, to: isoDay(new Date(`${selectedDay}T00:00:00Z`).getTime() + DAY) }
    : { from: since, to: null };
  const highlights = useMemo(() => buildHighlights(events, range), [events, range.from, range.to]);

  const changePeriod = (value: number) => {
    setPeriod(value);
    setSelectedDay(null);
  };
  const toggleCard = (key: string) => setExpanded((current) => (current.includes(key) ? current.filter((k) => k !== key) : [...current, key]));

  const entityLink = (event: TimelineEvent) => (
    <Box component="button" type="button" onClick={() => setSelected(event.matchId)} sx={{ font: 'inherit', fontWeight: 500, color: 'primary.main', cursor: 'pointer', border: 'none', background: 'none', p: 0 }}>
      {event.name}
    </Box>
  );
  const scoreMove = (event: TimelineEvent) => <ScoreMove event={event} />;
  // The entities of a card that sums several of them up, unfolded on demand
  const entityList = (card: Highlight, withScores: boolean) => (
    <>
      <Button variant="tertiary" size="small" onClick={() => toggleCard(card.key)}>
        {expanded.includes(card.key) ? t_i18n('Hide') : `${t_i18n('Show the')} ${card.events.length}`}
      </Button>
      {expanded.includes(card.key) && (
        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, mt: 1 }}>
          {card.events.slice(0, SHOWN_IN_CARD).map((e) => (
            <Box key={`${e.matchId}-${e.at}`} sx={{ display: 'flex', alignItems: 'center', gap: 0.5, border: '1px solid', borderColor: 'divider', borderRadius: 1, px: 0.75, py: 0.25 }}>
              {entityLink(e)}
              {withScores && scoreMove(e)}
            </Box>
          ))}
          {card.events.length > SHOWN_IN_CARD && <Text as="span" variant="content-caption">{`+${card.events.length - SHOWN_IN_CARD}`}</Text>}
        </Box>
      )}
    </>
  );

  const renderCard = (card: Highlight) => {
    const first = card.events[0];
    let sentence: ReactNode;
    let caption: string | null = null;
    let right: ReactNode = null;
    if (card.kind === 'crossed') {
      sentence = <>{entityLink(first)}{` ${t_i18n('is now above')} ${card.threshold}${first.changes.length > 0 ? `: ${first.changes.join(', ')}` : ''}`}</>;
      caption = first.trigger;
      right = scoreMove(first);
    } else if (card.kind === 'dropped') {
      sentence = <>{entityLink(first)}{card.threshold !== null ? ` ${t_i18n('fell below')} ${card.threshold}` : ` ${t_i18n('is no longer eligible')}`}</>;
      caption = first.trigger;
      right = scoreMove(first);
    } else if (card.kind === 'decision') {
      sentence = <>{entityLink(first)}{` · ${first.trigger}`}</>;
    } else if (card.kind === 'moves') {
      const up = card.events.filter((e) => e.toScore > (e.fromScore ?? 0)).length;
      sentence = `${card.events.length} ${t_i18n('other score changes, no threshold crossed')} (${up} ${t_i18n('up')}, ${card.events.length - up} ${t_i18n('down')})`;
      caption = null;
    } else if (card.kind === 'config') {
      const up = card.events.filter((e) => e.toScore > (e.fromScore ?? 0)).length;
      const down = card.events.filter((e) => e.toScore < (e.fromScore ?? 0)).length;
      const lost = card.events.filter((e) => e.eligibility === 'lost').length;
      sentence = `${card.trigger}: ${card.events.length} ${t_i18n('scores recalculated')} (${up} ${t_i18n('up')}, ${down} ${t_i18n('down')}${lost > 0 ? `, ${lost} ${t_i18n('no longer eligible')}` : ''})`;
    } else {
      sentence = `${card.events.length} ${t_i18n(card.events.length > 1 ? 'entities' : 'entity')} (${t_i18n(`entity_${card.entityType}`)}) · ${card.trigger}`;
      if (card.peak) {
        caption = card.days > 1
          ? `${t_i18n('over')} ${card.days} ${t_i18n('days')}, ${t_i18n('most on')} ${fsd(card.peak.day)} (${card.peak.count})`
          : `${t_i18n('on')} ${fsd(card.peak.day)}`;
      }
    }
    const summed = card.kind === 'moves' || card.kind === 'config' || card.kind === 'wave';
    return (
      <Box key={card.key} sx={{ border: '1px solid', borderColor: 'divider', borderRadius: 1, px: 1.5, py: 1.25, mb: 1, display: 'grid', gridTemplateColumns: 'auto minmax(0, 1fr) auto', columnGap: 1.5, alignItems: 'start' }}>
        <Box sx={{ pt: 0.25 }}><HighlightPill card={card} topThreshold={topThreshold} /></Box>
        <Box sx={{ minWidth: 0 }}>
          <Text as="div" variant="content-base">{sentence}</Text>
          {caption && <Text as="div" variant="content-caption" style={{ opacity: 0.7, marginTop: 2 }}>{caption}</Text>}
          {summed && entityList(card, card.kind !== 'wave')}
        </Box>
        <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 0.5 }}>
          {right}
          {!summed && <Text as="span" variant="content-caption" style={{ opacity: 0.7, whiteSpace: 'nowrap' }}>{fsd(card.at)}</Text>}
        </Box>
      </Box>
    );
  };

  let title = t_i18n('Since the creation');
  if (selectedDay) title = fld(selectedDay);
  else if (period > 0) title = `${t_i18n('Last')} ${period} ${t_i18n('days')}`;

  return (
    <>
      <Box sx={{ display: 'flex', alignItems: 'end', gap: 2, mb: 2 }}>
        <Box sx={{ width: 180 }}>
          <IrSelect
            label={t_i18n('Period')}
            value={String(period)}
            options={PERIODS.map((p) => ({ value: String(p), label: p === 0 ? t_i18n('Everything') : `${t_i18n('Last')} ${p} ${t_i18n('days')}` }))}
            onChange={(v) => changePeriod(Number(v))}
          />
        </Box>
        <Text as="span" variant="content-caption" style={{ opacity: 0.7, paddingBottom: 10 }}>{t_i18n('Click a day on the axis to see what happened that day.')}</Text>
      </Box>
      <Paper padding={16}>
        <IrTimelineAxis buckets={buckets} start={start} end={today} selectedDay={selectedDay} onSelectDay={setSelectedDay} />
      </Paper>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mt: 3, mb: 1.5 }}>
        <Text as="span" variant="title-sm">{title}</Text>
        {selectedDay && <Button variant="tertiary" size="small" onClick={() => setSelectedDay(null)}>{t_i18n('Back to the whole period')}</Button>}
      </Box>
      {highlights.length === 0 && <Text as="div" variant="content-base" style={{ opacity: 0.7 }}>{t_i18n('Nothing happened in this period.')}</Text>}
      {highlights.map(renderCard)}
      <IrMatchDrawer
        irId={irId}
        match={(matches.find((m) => m.id === selected) ?? null) as IrMatchData | null}
        criteria={criteria}
        onClose={() => setSelected(null)}
        onChanged={() => startTransition(() => setFetchKey((k) => k + 1))}
      />
    </>
  );
};

export default IrTimeline;
