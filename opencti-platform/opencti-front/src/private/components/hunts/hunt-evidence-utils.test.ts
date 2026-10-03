import { describe, expect, it } from 'vitest';
import { aggregateHuntEvidence, huntEvidenceFields, huntEvidenceWindow, type HuntEvidenceRun, shortHash } from './hunt-evidence-utils';

const runs: HuntEvidenceRun[] = [
  {
    id: 'run-1',
    completed_at: '2026-10-01T10:00:00.000Z',
    platform: 'Splunk prod',
    evidence_sample: [
      { field: 'process.command_line', value_hash: 'aaa', value_preview: 'powershell -enc', count: 3 },
      { field: 'source.ip', value_hash: 'bbb', value_preview: '10.0.0.1', count: 1 },
    ],
  },
  {
    id: 'run-2',
    completed_at: '2026-10-02T10:00:00.000Z',
    platform: 'Sentinel',
    evidence_sample: [
      { field: 'process.command_line', value_hash: 'aaa', value_preview: null, count: 4 },
      { field: 'host.name', value_hash: 'ccc', value_preview: 'srv-01', count: 2 },
    ],
  },
  { id: 'run-3', completed_at: '2026-10-03T10:00:00.000Z', platform: 'Splunk prod', evidence_sample: null },
];

describe('Hunt evidence utils', () => {
  describe('aggregateHuntEvidence()', () => {
    it('should merge the same hashed value across runs and sort by count', () => {
      const rows = aggregateHuntEvidence(runs);
      expect(rows.map((row) => row.id)).toEqual(['process.command_line::aaa', 'host.name::ccc', 'source.ip::bbb']);
      expect(rows[0]).toEqual({
        id: 'process.command_line::aaa',
        field: 'process.command_line',
        value_hash: 'aaa',
        value_preview: 'powershell -enc',
        count: 7,
        runs_count: 2,
        run_ids: ['run-1', 'run-2'],
        platforms: ['Splunk prod', 'Sentinel'],
        first_seen_at: '2026-10-01T10:00:00.000Z',
        last_seen_at: '2026-10-02T10:00:00.000Z',
      });
    });

    it('should filter by run, field and search term', () => {
      expect(aggregateHuntEvidence(runs, { runIds: ['run-2'] }).map((row) => row.count)).toEqual([4, 2]);
      expect(aggregateHuntEvidence(runs, { field: 'source.ip' }).map((row) => row.id)).toEqual(['source.ip::bbb']);
      expect(aggregateHuntEvidence(runs, { search: 'srv' }).map((row) => row.id)).toEqual(['host.name::ccc']);
      expect(aggregateHuntEvidence(runs, { search: 'bb' }).map((row) => row.id)).toEqual(['source.ip::bbb']);
    });

    it('should return no row without evidence', () => {
      expect(aggregateHuntEvidence([])).toEqual([]);
      expect(aggregateHuntEvidence([runs[2]])).toEqual([]);
    });
  });

  it('should list the distinct evidence fields', () => {
    expect(huntEvidenceFields(runs)).toEqual(['host.name', 'process.command_line', 'source.ip']);
  });

  it('should shorten long hashes only', () => {
    expect(shortHash('0123456789abcdef')).toEqual('0123456789ab...');
    expect(shortHash('abc')).toEqual('abc');
  });

  it('should name the window of the loaded runs when older completed runs exist', () => {
    const recentFirst: HuntEvidenceRun[] = [
      { id: 'run-new', completed_at: '2026-10-03T10:00:00.000Z' },
      { id: 'run-old', completed_at: null, created_at: '2026-09-01T08:00:00.000Z' },
    ];
    expect(huntEvidenceWindow(recentFirst, 250)).toEqual({ completedRunsCount: 250, isWindowed: true, since: '2026-09-01T08:00:00.000Z' });
    expect(huntEvidenceWindow(recentFirst, 2)).toEqual({ completedRunsCount: 2, isWindowed: false, since: '2026-09-01T08:00:00.000Z' });
    expect(huntEvidenceWindow(recentFirst, null)).toEqual({ completedRunsCount: 2, isWindowed: false, since: '2026-09-01T08:00:00.000Z' });
    expect(huntEvidenceWindow([], 0)).toEqual({ completedRunsCount: 0, isWindowed: false, since: null });
  });
});
