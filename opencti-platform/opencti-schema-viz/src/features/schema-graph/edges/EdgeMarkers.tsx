import { MARKER_IDS } from './edgeData';

const ARROW_FILLS = {
  relationship: 'var(--sv-edge-relationship)',
  ref: 'var(--sv-edge-ref)',
  highlighted: 'var(--sv-edge-highlight)',
} as const;

export const EdgeMarkers = () => (
  <svg className="sv-edge-markers" aria-hidden="true">
    <defs>
      <marker id={MARKER_IDS.inheritance} viewBox="0 0 12 12" refX="1" refY="6" markerWidth="12" markerHeight="12" orient="auto-start-reverse">
        <path d="M11 1 1 6l10 5z" strokeWidth="1.3" strokeLinejoin="round" style={{ fill: 'var(--sv-surface-canvas)', stroke: 'var(--sv-edge-inheritance)' }} />
      </marker>
      {(Object.keys(ARROW_FILLS) as Array<keyof typeof ARROW_FILLS>).map((tone) => (
        <marker key={tone} id={MARKER_IDS[tone]} viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto">
          <path d="M1 1 9 5 1 9z" style={{ fill: ARROW_FILLS[tone] }} />
        </marker>
      ))}
    </defs>
  </svg>
);
