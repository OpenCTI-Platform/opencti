import { describe, expect, it } from 'vitest';
import {
  CONFIG_PRESET_IMPORT_PROBLEMS_LIMIT,
  CONFIG_PRESET_IMPORT_RECENT_LIMIT,
  configPresetResultBucket,
  type ConfigPresetImportItemResult,
  type ConfigPresetImportSession,
  getConfigPresetImportAvailableEvents,
  isConfigPresetResultProblem,
  summarizeConfigPresetImportResults,
  toConfigPresetImportTypeCounts,
  transitionConfigPresetImportSession as transition,
} from '../../../../../src/modules/configPreset/import/configPreset-import-session';

const selections = [{ type: 'messages', items: ['banner'], excluded_items: null }];
const draft = (overrides: Partial<ConfigPresetImportSession> = {}): ConfigPresetImportSession => ({
  ...transition(null, 'UPLOAD', { platform_id: 'platform', file_id: 'file-1' })!,
  ...overrides,
});
const applying = () => transition(draft(), 'START', { started_at: '2026-10-27T10:00:00.000Z', total: 2, selections })!;
const finished = () => transition(applying(), 'FINISH', {
  outcome: 'COMPLETED',
  counts: { created: 1, overwritten: 1, skipped: 0, failed: 0 },
  report_id: 'report',
})!;
const refused = (session: ConfigPresetImportSession | null, event: Parameters<typeof transition>[1], payload: never) => {
  expect(() => transition(session, event, payload)).toThrowError('This action is not available in the current state of the import');
};

describe('Config preset import session transitions', () => {
  it('uploads a zip: a draft with an empty selection, from no session, a draft or a finished import', () => {
    const payload = { platform_id: 'platform', file_id: 'file-2' };
    [null, draft({ selections, revision: 3 }), finished()].forEach((session) => {
      expect(transition(session, 'UPLOAD', payload)).toMatchObject({ status: 'DRAFT', file_id: 'file-2', selections: [], revision: 0, results: [], outcome: null });
    });
  });

  it('refuses an upload, a save, a start over and a start while applying', () => {
    refused(applying(), 'UPLOAD', { platform_id: 'platform', file_id: 'f' } as never);
    refused(applying(), 'SAVE', { file_id: 'file-1', selections, revision: 1 } as never);
    refused(applying(), 'START_OVER', undefined as never);
    refused(applying(), 'START', { started_at: 'x', total: 1, selections } as never);
    refused(applying(), 'CLOSE', undefined as never);
  });

  it('saves the selection of a draft for its own file only', () => {
    const saved = transition(draft(), 'SAVE', { file_id: 'file-1', selections, revision: 1 });
    expect(saved).toMatchObject({ status: 'DRAFT', selections, revision: 1 });
    expect(() => transition(draft(), 'SAVE', { file_id: 'other-file', selections, revision: 1 })).toThrowError('no longer exists');
    refused(null, 'SAVE', { file_id: 'file-1', selections, revision: 1 } as never);
    refused(finished(), 'SAVE', { file_id: 'file-1', selections, revision: 1 } as never);
  });

  it('ignores a save with a lower revision', () => {
    const current = draft({ selections, revision: 5 });
    expect(transition(current, 'SAVE', { file_id: 'file-1', selections: [], revision: 4 })).toBe(current);
    expect(transition(current, 'SAVE', { file_id: 'file-1', selections: [], revision: 5 })).toMatchObject({ selections: [], revision: 5 });
  });

  it('starts only from a draft and replaces the selection with the one it is given', () => {
    const started = transition(draft({ selections: [], revision: 2 }), 'START', { started_at: '2026-10-27T10:00:00.000Z', total: 3, selections })!;
    expect(started).toMatchObject({ status: 'APPLYING', started_at: '2026-10-27T10:00:00.000Z', total: 3, selections, results: [] });
    refused(null, 'START', { started_at: 'x', total: 1, selections } as never);
    refused(finished(), 'START', { started_at: 'x', total: 1, selections } as never);
  });

  it('accepts the result of a processed item while applying only, and leaves the session as it is: the results have a list of their own', () => {
    const result = { type: 'messages', key: 'banner', status: 'OVERWRITTEN' as const, reason: null };
    const session = applying();
    expect(transition(session, 'ITEM_PROCESSED', { result })).toBe(session);
    refused(draft(), 'ITEM_PROCESSED', { result } as never);
  });

  it('finishes with the outcome, the counts and the report, and keeps them', () => {
    const done = finished();
    expect(done).toMatchObject({ status: 'FINISHED', outcome: 'COMPLETED', report_id: 'report', counts: { created: 1, overwritten: 1, skipped: 0, failed: 0 } });
    refused(draft(), 'FINISH', { outcome: 'COMPLETED', counts: {}, report_id: null } as never);
  });

  it('starts over from a draft or a finished import, and closes a finished import only', () => {
    expect(transition(draft(), 'START_OVER', undefined)).toBeNull();
    expect(transition(finished(), 'START_OVER', undefined)).toBeNull();
    expect(transition(finished(), 'CLOSE', undefined)).toBeNull();
    refused(null, 'START_OVER', undefined as never);
    refused(draft(), 'CLOSE', undefined as never);
    refused(null, 'CLOSE', undefined as never);
  });

  it('goes back to the draft from applying, keeping the file and the selection, and from nowhere else', () => {
    const back = transition(applying(), 'ABORT', undefined)!;
    expect(back).toMatchObject({ status: 'DRAFT', file_id: 'file-1', selections, started_at: null, total: 0, results: [] });
    refused(draft(), 'ABORT', undefined as never);
    refused(finished(), 'ABORT', undefined as never);
    refused(null, 'ABORT', undefined as never);
  });

  it('finishes with the outcome stopped', () => {
    expect(transition(applying(), 'FINISH', { outcome: 'STOPPED', counts: { created: 0, overwritten: 0, skipped: 0, failed: 2 }, report_id: null })).toMatchObject({ status: 'FINISHED', outcome: 'STOPPED' });
  });

  describe('interrupted (derived, never stored)', () => {
    const interrupted = () => ({ ...applying(), results: [{ type: 'messages', key: 'banner', status: 'OVERWRITTEN' as const, reason: null }], status: 'INTERRUPTED' as const });

    it('goes back to the selection keeping the file and the selection, and drops the progress', () => {
      expect(transition(interrupted(), 'BACK_TO_SELECTION', undefined)).toMatchObject({ status: 'DRAFT', file_id: 'file-1', selections, started_at: null, total: 0, results: [] });
    });

    it('starts over, and refuses everything else', () => {
      expect(transition(interrupted(), 'START_OVER', undefined)).toBeNull();
      refused(interrupted(), 'UPLOAD', { platform_id: 'platform', file_id: 'f' } as never);
      refused(interrupted(), 'SAVE', { file_id: 'file-1', selections, revision: 9 } as never);
      refused(interrupted(), 'START', { started_at: 'x', total: 1, selections } as never);
      refused(interrupted(), 'CLOSE', undefined as never);
      refused(interrupted(), 'FINISH', { outcome: 'COMPLETED', counts: {}, report_id: null } as never);
    });

    it('refuses back to the selection from any other state', () => {
      [null, draft(), applying(), finished()].forEach((session) => refused(session, 'BACK_TO_SELECTION', undefined as never));
    });

    it('offers back to the selection and start over', () => {
      expect(getConfigPresetImportAvailableEvents(interrupted())).toEqual(['START_OVER', 'BACK_TO_SELECTION']);
    });
  });

  // The API returns a session (not null) for SAVE and BACK_TO_SELECTION: the guard of the domain relies on it
  it('keeps a session with the events that return a session, from every state that accepts them', () => {
    expect(transition(draft(), 'SAVE', { file_id: 'file-1', selections, revision: 1 })).not.toBeNull();
    expect(transition(draft({ revision: 5 }), 'SAVE', { file_id: 'file-1', selections, revision: 1 })).not.toBeNull();
    expect(transition({ ...applying(), status: 'INTERRUPTED' }, 'BACK_TO_SELECTION', undefined)).not.toBeNull();
  });

  it('lists the events each state accepts', () => {
    expect(getConfigPresetImportAvailableEvents(null)).toEqual(['UPLOAD']);
    expect(getConfigPresetImportAvailableEvents(draft())).toEqual(['UPLOAD', 'SAVE', 'START_OVER', 'START']);
    expect(getConfigPresetImportAvailableEvents(applying())).toEqual(['ITEM_PROCESSED', 'FINISH', 'ABORT']);
    expect(getConfigPresetImportAvailableEvents(finished())).toEqual(['UPLOAD', 'START_OVER', 'CLOSE']);
  });
});

describe('What the screens show of a run', () => {
  const result = (type: string, key: string, status: ConfigPresetImportItemResult['status'], code: string | null = null): ConfigPresetImportItemResult => ({
    type,
    key,
    status,
    reason: status === 'FAILED' || status === 'SKIPPED' ? 'a reason' : null,
    code,
  });

  it('counts an item the platform had as it is apart from the ones that were skipped', () => {
    expect(configPresetResultBucket(result('labels', 'a', 'CREATED'))).toBe('created');
    expect(configPresetResultBucket(result('labels', 'a', 'OVERWRITTEN'))).toBe('overwritten');
    expect(configPresetResultBucket(result('labels', 'a', 'FAILED'))).toBe('failed');
    expect(configPresetResultBucket(result('labels', 'a', 'SKIPPED', 'unchanged'))).toBe('unchanged');
    expect(configPresetResultBucket(result('labels', 'a', 'SKIPPED', 'nothing_to_import'))).toBe('skipped');
    expect(configPresetResultBucket(result('labels', 'a', 'SKIPPED'))).toBe('skipped');
  });

  it('calls a problem what failed or was skipped for a reason, not what is up to date', () => {
    expect(isConfigPresetResultProblem(result('labels', 'a', 'FAILED'))).toBe(true);
    expect(isConfigPresetResultProblem(result('labels', 'a', 'SKIPPED', 'nothing_to_import'))).toBe(true);
    expect(isConfigPresetResultProblem(result('labels', 'a', 'SKIPPED', 'unchanged'))).toBe(false);
    expect(isConfigPresetResultProblem(result('labels', 'a', 'CREATED'))).toBe(false);
    expect(isConfigPresetResultProblem(result('labels', 'a', 'OVERWRITTEN'))).toBe(false);
  });

  it('reads the counts by type from the counters of a run, and ignores a field it does not know', () => {
    expect(toConfigPresetImportTypeCounts({ 'labels|created': '120', 'labels|failed': '3', 'messages|overwritten': '1', 'labels|unknown': '9', broken: '2' })).toEqual([
      { type: 'labels', created: 120, overwritten: 0, unchanged: 0, skipped: 0, failed: 3 },
      { type: 'messages', created: 0, overwritten: 1, unchanged: 0, skipped: 0, failed: 0 },
    ]);
    expect(toConfigPresetImportTypeCounts({})).toEqual([]);
  });

  it('summarizes the results of a session that kept them inside it: counts, first problems, last items', () => {
    const results = [
      ...Array.from({ length: 30 }, (_, i) => result('labels', `ok-${i}`, 'CREATED')),
      ...Array.from({ length: CONFIG_PRESET_IMPORT_PROBLEMS_LIMIT + 20 }, (_, i) => result('labels', `ko-${i}`, 'FAILED')),
      result('messages', 'banner', 'SKIPPED', 'unchanged'),
    ];
    const summary = summarizeConfigPresetImportResults(results);
    expect(summary.processed).toBe(results.length);
    expect(summary.type_counts).toEqual([
      { type: 'labels', created: 30, overwritten: 0, unchanged: 0, skipped: 0, failed: CONFIG_PRESET_IMPORT_PROBLEMS_LIMIT + 20 },
      { type: 'messages', created: 0, overwritten: 0, unchanged: 1, skipped: 0, failed: 0 },
    ]);
    expect(summary.problems).toHaveLength(CONFIG_PRESET_IMPORT_PROBLEMS_LIMIT);
    expect(summary.problems[0].key).toBe('ko-0');
    expect(summary.recent.map(({ key }) => key)).toEqual(results.slice(-CONFIG_PRESET_IMPORT_RECENT_LIMIT).map(({ key }) => key));
  });
});
