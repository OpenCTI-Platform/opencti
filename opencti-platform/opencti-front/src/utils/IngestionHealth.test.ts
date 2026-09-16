import { describe, expect, it } from 'vitest';
import {
  buildHealthTooltipLines,
  countHealthStatuses,
  HEALTH_PALETTE_TOKEN,
  isAttentionStatus,
} from './IngestionHealth';

describe('HEALTH_PALETTE_TOKEN', () => {
  it('keeps deliberately stopped and not-due-yet sources neutral', () => {
    // Colouring these would train users to ignore the whole column.
    expect(HEALTH_PALETTE_TOKEN.stopped).toBe('neutral');
    expect(HEALTH_PALETTE_TOKEN.idle).toBe('neutral');
    expect(HEALTH_PALETTE_TOKEN.unknown).toBe('neutral');
  });

  it('maps the actionable statuses onto palette tokens, never raw colours', () => {
    expect(HEALTH_PALETTE_TOKEN.critical).toBe('error');
    expect(HEALTH_PALETTE_TOKEN.degraded).toBe('warn');
    expect(HEALTH_PALETTE_TOKEN.healthy).toBe('success');
  });
});

describe('isAttentionStatus', () => {
  it('counts only critical and degraded as needing attention', () => {
    expect(isAttentionStatus('critical')).toBe(true);
    expect(isAttentionStatus('degraded')).toBe(true);
    expect(isAttentionStatus('stopped')).toBe(false);
    expect(isAttentionStatus(null)).toBe(false);
  });
});

describe('countHealthStatuses', () => {
  it('counts by status and ignores sources with no health yet', () => {
    const counts = countHealthStatuses([
      { ingestion_health: { status: 'critical' } },
      { ingestion_health: { status: 'degraded' } },
      { ingestion_health: { status: 'degraded' } },
      { ingestion_health: { status: 'healthy' } },
      { ingestion_health: null },
      {},
    ]);
    expect(counts.critical).toBe(1);
    expect(counts.degraded).toBe(2);
    // healthy is counted in the total but has no counter of its own.
    expect(counts.total).toBe(4);
  });
});

describe('buildHealthTooltipLines', () => {
  it('returns nothing when health is unavailable', () => {
    expect(buildHealthTooltipLines(null)).toEqual([]);
  });

  it('leads with the summary and does not repeat it', () => {
    const lines = buildHealthTooltipLines({
      status: 'degraded',
      summary: 'Degraded — ran 3 times without importing any object',
      checks: [
        { kind: 'runtime', code: 'EMPTY_RUNS', severity: 'advisory', message: 'Ran 3 times without importing any object' },
        { kind: 'runtime', code: 'RUN_OVERDUE', severity: 'advisory', message: 'Expected to run earlier' },
      ],
    });
    expect(lines[0]).toMatch(/^Degraded —/);
    expect(lines).toHaveLength(2);
    expect(lines[1]).toBe('Expected to run earlier');
  });
});
