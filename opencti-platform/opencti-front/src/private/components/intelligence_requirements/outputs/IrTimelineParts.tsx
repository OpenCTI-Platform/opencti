import React from 'react';
import { Chip, Text } from '@filigran/design-system';
import Box from '@mui/material/Box';
import { ArrowDownward, ArrowUpward } from '@mui/icons-material';
import { useFormatter } from '../../../../components/i18n';
import type { Highlight, TimelineEvent } from './irTimelineEvents';

// Pieces shared by the Timeline tab and its preview on the Overview.

// A score that moved: "↑ 50 → 100", green upwards, red downwards; nothing when it did not move
export const ScoreMove = ({ event }: { event: TimelineEvent }) => {
  if (event.fromScore === null || event.fromScore === event.toScore) return null;
  const up = event.toScore > event.fromScore;
  return (
    <Box component="span" sx={{ display: 'inline-flex', alignItems: 'center', gap: 0.25, color: up ? 'success.main' : 'error.main', whiteSpace: 'nowrap' }}>
      {up ? <ArrowUpward sx={{ fontSize: 14 }} /> : <ArrowDownward sx={{ fontSize: 14 }} />}
      <Text as="span" variant="content-compact-bold">{`${event.fromScore} → ${event.toScore}`}</Text>
    </Box>
  );
};

// What a card is about: a threshold crossed (critical for the highest one), a drop, a decision, a wave of entries...
export const HighlightPill = ({ card, topThreshold }: { card: Highlight; topThreshold: number }) => {
  const { t_i18n } = useFormatter();
  switch (card.kind) {
    case 'crossed':
      return <Chip label={`${t_i18n('Crossed')} ${card.threshold}`} severity={card.threshold === topThreshold ? 'critical' : 'high'} size="sm" />;
    case 'dropped':
      return <Chip label={card.threshold !== null ? `${t_i18n('Below')} ${card.threshold}` : t_i18n('Not eligible')} size="sm" />;
    case 'decision':
      return <Chip label={t_i18n('Decision')} severity="info" size="sm" />;
    case 'moves':
      return <Chip label={t_i18n('Score changes')} size="sm" />;
    case 'config':
      return <Chip label={t_i18n('Configuration')} size="sm" />;
    default:
      return <Chip label={t_i18n('Entries')} severity="info" size="sm" />;
  }
};
