import { describe, expect, it } from 'vitest';
import { buildTimelineStatuses, capTimelineRead } from '../../../../src/modules/timeline/timeline-loader';

describe('Timeline derivation input bounds', () => {
  it('should keep a family within its bound untouched and not report a truncation', () => {
    const bounds = { truncated: false };
    expect(capTimelineRead(bounds, [1, 2, 3], 3)).toEqual([1, 2, 3]);
    expect(capTimelineRead(bounds, [], 3)).toEqual([]);
    expect(bounds.truncated).toBe(false);
  });

  it('should cap a family read one item past its bound and report the truncation', () => {
    const bounds = { truncated: false };
    expect(capTimelineRead(bounds, [1, 2, 3, 4], 3)).toEqual([1, 2, 3]);
    expect(bounds.truncated).toBe(true);
  });

  it('should keep the truncation reported by an earlier family', () => {
    const bounds = { truncated: false };
    capTimelineRead(bounds, ['a', 'b'], 1);
    expect(capTimelineRead(bounds, ['c'], 5)).toEqual(['c']);
    expect(bounds.truncated).toBe(true);
  });
});

describe('Timeline workflow statuses', () => {
  const status = (internal_id: string, type: string, order: number, scope?: string | null) => ({ internal_id, name: internal_id, type, order, scope });

  it('should mark the last status of each type as final', () => {
    const statuses = buildTimelineStatuses([
      status('incident-new', 'Case-Incident', 1, 'GLOBAL'),
      status('incident-closed', 'Case-Incident', 5, 'GLOBAL'),
      status('rft-new', 'Case-Rft', 1, 'GLOBAL'),
      status('rft-closed', 'Case-Rft', 2, 'GLOBAL'),
    ]);
    expect(statuses.get('incident-closed')?.is_final).toBe(true);
    expect(statuses.get('incident-new')?.is_final).toBe(false);
    expect(statuses.get('rft-closed')?.is_final).toBe(true);
    expect(statuses.get('rft-new')?.is_final).toBe(false);
  });

  it('should compute the final status of each workflow scope independently', () => {
    const statuses = buildTimelineStatuses([
      status('rfi-new', 'Case-Rfi', 1, 'GLOBAL'),
      status('rfi-closed', 'Case-Rfi', 3, 'GLOBAL'),
      status('access-new', 'Case-Rfi', 1, 'REQUEST_ACCESS'),
      status('access-approved', 'Case-Rfi', 7, 'REQUEST_ACCESS'),
    ]);
    // A higher order in the request access workflow never makes the case workflow's last status non-final
    expect(statuses.get('rfi-closed')?.is_final).toBe(true);
    expect(statuses.get('access-approved')?.is_final).toBe(true);
    expect(statuses.get('rfi-new')?.is_final).toBe(false);
    expect(statuses.get('access-new')?.is_final).toBe(false);
  });

  it('should read a status without scope as part of the case workflow', () => {
    const statuses = buildTimelineStatuses([
      status('legacy-new', 'Case-Incident', 1, null),
      status('incident-closed', 'Case-Incident', 4, 'GLOBAL'),
    ]);
    expect(statuses.get('incident-closed')?.is_final).toBe(true);
    expect(statuses.get('legacy-new')?.is_final).toBe(false);
  });
});
