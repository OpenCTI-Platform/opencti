import React, { useMemo } from 'react';
import { Link, useNavigate } from 'react-router';
import { Paper, Text } from '@filigran/design-system';
import Box from '@mui/material/Box';
import { useFormatter } from '../../../../components/i18n';
import IrTimelineAxis from './IrTimelineAxis';
import { HighlightPill, ScoreMove } from './IrTimelineParts';
import { buildHighlights, dailyBuckets, timelineEvents, type TimelineMatch } from './irTimelineEvents';

// Preview of the timeline on the Overview: the last 30 days on one lane, and the first facts that deserve attention.
// Facts only, no action: what is left to do is the Inbox.

const PERIOD = 30;
const SHOWN = 3;
const DAY = 24 * 3600 * 1000;
const isoDay = (time: number) => new Date(time).toISOString().slice(0, 10);

interface IrTimelinePreviewProps {
  irId: string;
  matches: readonly TimelineMatch[];
  thresholds: readonly number[];
  onOpen: (matchId: string) => void;
}

const IrTimelinePreview = ({ irId, matches, thresholds, onOpen }: IrTimelinePreviewProps) => {
  const { t_i18n, fsd } = useFormatter();
  const navigate = useNavigate();
  const timelinePath = `/dashboard/intelligence_requirements/${irId}/timeline`;
  const today = isoDay(Date.now());
  const since = isoDay(Date.now() - (PERIOD - 1) * DAY);
  const events = useMemo(() => timelineEvents(matches, thresholds), [matches, thresholds]);
  const buckets = useMemo(() => dailyBuckets(events, since), [events, since]);
  const highlights = useMemo(() => buildHighlights(events, { from: since, to: null }), [events, since]);
  const facts = highlights.filter((h) => h.kind !== 'wave' && h.kind !== 'config' && h.kind !== 'moves').slice(0, SHOWN);
  const others = highlights.filter((h) => h.kind !== 'wave').length - facts.length;
  const entries = buckets.reduce((n, b) => n + b.entry, 0);
  const peak = buckets.reduce<{ day: string; entry: number } | null>((best, b) => (b.entry > (best?.entry ?? 0) ? b : best), null);
  const topThreshold = Math.max(...thresholds, 0);

  return (
    <Paper padding={16}>
      <Box sx={{ display: 'flex', alignItems: 'baseline', gap: 1, mb: 1 }}>
        <Text as="span" variant="title-sm">{t_i18n('{count, plural, one {Last day} other {Last # days}}', { values: { count: PERIOD } })}</Text>
        <Text as="span" variant="content-caption" style={{ opacity: 0.7 }}>
          {entries > 0 && peak
            ? `${t_i18n('{count, plural, one {# entry} other {# entries}}', { values: { count: entries } })}, ${t_i18n('most on')} ${fsd(peak.day)} (${peak.entry})`
            : t_i18n('no entry')}
        </Text>
        <Box sx={{ flex: 1 }} />
        <Link to={timelinePath}>{t_i18n('See the timeline')}</Link>
      </Box>
      <Box sx={{ display: 'grid', gridTemplateColumns: { xs: 'minmax(0, 1fr)', lg: 'minmax(0, 1.3fr) minmax(0, 1fr)' }, gap: 3, alignItems: 'center' }}>
        <IrTimelineAxis
          compact
          buckets={buckets}
          start={since}
          end={today}
          selectedDay={null}
          onSelectDay={(day) => day && navigate(`${timelinePath}?day=${day}`)}
        />
        <Box>
          {facts.length === 0 && (
            <Text as="div" variant="content-caption" style={{ opacity: 0.7 }}>{t_i18n('No threshold crossed and no decision in this period.')}</Text>
          )}
          {facts.map((card) => {
            const event = card.events[0];
            return (
              <Box key={card.key} sx={{ display: 'grid', gridTemplateColumns: 'auto minmax(0, 1fr) auto auto', columnGap: 1, alignItems: 'center', py: 0.75, borderBottom: '1px solid', borderColor: 'divider' }}>
                <HighlightPill card={card} topThreshold={topThreshold} />
                <Box
                  component="button"
                  type="button"
                  onClick={() => onOpen(event.matchId)}
                  sx={{ font: 'inherit', fontWeight: 500, color: 'primary.main', cursor: 'pointer', border: 'none', background: 'none', p: 0, textAlign: 'left', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
                >
                  {event.name}
                </Box>
                <ScoreMove event={event} />
                <Text as="span" variant="content-caption" style={{ opacity: 0.7, whiteSpace: 'nowrap' }}>{fsd(card.at)}</Text>
              </Box>
            );
          })}
          {others > 0 && (
            <Box sx={{ mt: 0.75 }}>
              <Link to={timelinePath}>{t_i18n('{count, plural, one {+ # other fact} other {+ # other facts}}', { values: { count: others } })}</Link>
            </Box>
          )}
        </Box>
      </Box>
    </Paper>
  );
};

export default IrTimelinePreview;
