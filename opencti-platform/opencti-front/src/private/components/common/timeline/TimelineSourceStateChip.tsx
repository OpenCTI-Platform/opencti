import React from 'react';
import { Chip } from '@filigran/design-system';
import { useFormatter } from '../../../../components/i18n';
import { resolveTimelineSourceState, type TimelineSourceStateValue } from './timelineSourceStates';

/** State of the run, step or deployment an event comes from, in the vocabulary of its owner; nothing when unknown. */
const TimelineSourceStateChip = ({ state }: { state: TimelineSourceStateValue | null | undefined }) => {
  const { t_i18n } = useFormatter();
  const chip = resolveTimelineSourceState(state);
  if (!chip) return null;
  return (
    <Chip
      label={t_i18n(chip.label)}
      severity={chip.severity}
      size="sm"
      style={chip.dimmed ? { opacity: 0.6 } : undefined}
      data-testid="timeline-source-state"
    />
  );
};

export default TimelineSourceStateChip;
