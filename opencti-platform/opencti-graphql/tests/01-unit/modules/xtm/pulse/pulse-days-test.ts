import { describe, expect, it } from 'vitest';
import { utcDaySegments } from '../../../../../src/modules/xtm/pulse/pulse-domain';

const at = (iso: string) => new Date(iso);
const asIso = (segments: ReturnType<typeof utcDaySegments>) => segments.map(({ day, since, until }) => ({ day, since: since.toISOString(), until: until.toISOString() }));

describe('Threat Pulse contribution days', () => {
  it('should keep a window inside one UTC day as one part', () => {
    expect(asIso(utcDaySegments(at('2026-10-03T10:00:00.000Z'), at('2026-10-03T11:00:00.000Z')))).toEqual([
      { day: '2026-10-03', since: '2026-10-03T10:00:00.000Z', until: '2026-10-03T11:00:00.000Z' },
    ]);
  });

  it('should cut a window at UTC midnight so that each part carries its own day', () => {
    expect(asIso(utcDaySegments(at('2026-10-03T23:10:00.000Z'), at('2026-10-04T00:10:00.000Z')))).toEqual([
      { day: '2026-10-03', since: '2026-10-03T23:10:00.000Z', until: '2026-10-04T00:00:00.000Z' },
      { day: '2026-10-04', since: '2026-10-04T00:00:00.000Z', until: '2026-10-04T00:10:00.000Z' },
    ]);
  });

  it('should cut a catch-up window at every midnight it crosses', () => {
    const segments = utcDaySegments(at('2026-10-02T12:00:00.000Z'), at('2026-10-04T06:00:00.000Z'));
    expect(segments.map(({ day }) => day)).toEqual(['2026-10-02', '2026-10-03', '2026-10-04']);
    expect(segments[1].since.toISOString()).toBe('2026-10-03T00:00:00.000Z');
    expect(segments[1].until.toISOString()).toBe('2026-10-04T00:00:00.000Z');
  });

  it('should return nothing for an empty window', () => {
    expect(utcDaySegments(at('2026-10-03T10:00:00.000Z'), at('2026-10-03T10:00:00.000Z'))).toEqual([]);
  });
});
