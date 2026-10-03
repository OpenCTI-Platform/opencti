import React from 'react';
import { Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { useFormatter } from '../../../../components/i18n';
import useTimelineColors from './useTimelineColors';
import { TIMELINE_ANCHOR_KEYS, TIMELINE_ANCHOR_LABELS, type TimelineAnchorKey, toTime } from './timelineUtils';
import type { TimelineChartAnchors } from './ContainerTimelineLanes';

const ANCHOR_HELP: Record<TimelineAnchorKey, string> = {
  first_adversary_activity: 'First event of the adversary lane',
  first_detection: 'First event of the detection lane (security platform sightings, coverage results, hunts, deployments)',
  first_response: 'First event of the response lane',
  containment: 'First containment milestone or completion of a task labelled containment',
  closure: 'Last transition to the final workflow status, while the case stays closed',
};

interface ContainerTimelineAnchorsProps {
  anchors: TimelineChartAnchors;
  dense?: boolean;
  onAnchorClick?: (time: number) => void;
}

/** Per-case anchor timestamps (no aggregated metric): one tile per anchor, empty when not reached yet. */
const ContainerTimelineAnchors = ({ anchors, dense = false, onAnchorClick }: ContainerTimelineAnchorsProps) => {
  const { t_i18n, fldt, nsdt } = useFormatter();
  const colors = useTimelineColors();
  return (
    <div
      role="list"
      aria-label={t_i18n('Timeline anchors')}
      style={{ display: 'grid', gridTemplateColumns: `repeat(${TIMELINE_ANCHOR_KEYS.length}, minmax(0, 1fr))`, gap: dense ? 6 : 10 }}
      data-testid="timeline-anchors"
    >
      {TIMELINE_ANCHOR_KEYS.map((key) => {
        const value = anchors?.[key] ?? null;
        const time = toTime(value);
        const content = (
          <div
            role="listitem"
            style={{
              border: `1px solid ${colors.grid}`,
              borderRadius: 4,
              padding: dense ? '4px 8px' : '8px 10px',
              cursor: time !== null && onAnchorClick ? 'pointer' : 'default',
              minWidth: 0,
            }}
            tabIndex={time !== null && onAnchorClick ? 0 : undefined}
            onClick={() => time !== null && onAnchorClick?.(time)}
            onKeyDown={(event) => {
              if ((event.key === 'Enter' || event.key === ' ') && time !== null && onAnchorClick) {
                event.preventDefault();
                onAnchorClick(time);
              }
            }}
            data-testid={`timeline-anchor-${key}`}
          >
            <div style={{ fontSize: 11, color: colors.textSecondary, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
              {t_i18n(TIMELINE_ANCHOR_LABELS[key])}
            </div>
            <div style={{ fontSize: dense ? 12 : 13, fontWeight: 600, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
              {value ? (dense ? nsdt(value) : fldt(value)) : '-'}
            </div>
          </div>
        );
        return (
          <Tooltip key={key}>
            <TooltipTrigger asChild>{content}</TooltipTrigger>
            <TooltipContent>{t_i18n(ANCHOR_HELP[key])}</TooltipContent>
          </Tooltip>
        );
      })}
    </div>
  );
};

export default ContainerTimelineAnchors;
