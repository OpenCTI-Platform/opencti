import { beforeEach, describe, expect, it, vi } from 'vitest';
import { curationManagerStreamHandler } from '../../../src/manager/curationManager';
import { redisCurationPushDeadLetters, redisSetManagerEventState } from '../../../src/database/redis';
import { persistProposalDraft } from '../../../src/modules/curation/curation-proposals';
import { runIncrementalDuplicateDetection } from '../../../src/modules/curation/curation-scan';
import type { DataEvent, SseEvent } from '../../../src/types/event';

vi.mock('../../../src/manager/managerModule', () => ({ registerManager: vi.fn() }));

vi.mock('../../../src/database/redis', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/database/redis')>()),
  redisCurationPushDeadLetters: vi.fn(),
  redisCurationTakeDeadLetters: vi.fn(async () => []),
  redisGetManagerEventState: vi.fn(),
  redisSetManagerEventState: vi.fn(),
}));

vi.mock('../../../src/modules/curation/curation-settings', () => ({
  getCurationSettings: vi.fn(async () => ({ curation_enabled: true, curated_entity_types: [], enabled_detectors: ['contradiction'] })),
  saveCurationSettings: vi.fn(),
}));

vi.mock('../../../src/modules/curation/curation-proposals', () => ({ persistProposalDraft: vi.fn() }));

vi.mock('../../../src/modules/curation/curation-scan', () => ({
  runContradictionScan: vi.fn(),
  runDuplicateScan: vi.fn(),
  runIncrementalDuplicateDetection: vi.fn(),
  runStalenessScan: vi.fn(),
}));

const POISON_ID = 'malware-poison';

// A creation with inverted dates: the contradiction detector turns it into a proposal draft.
const invertedDates = (eventId: string, entityId: string) => ({
  id: eventId,
  event: 'create',
  data: {
    type: 'create',
    data: {
      name: entityId,
      first_seen: '2024-02-01T00:00:00.000Z',
      last_seen: '2024-01-01T00:00:00.000Z',
      extensions: { 'extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba': { id: entityId, type: 'Malware' } },
    },
  },
}) as unknown as SseEvent<DataEvent>;

describe('Curation manager stream handler', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    (persistProposalDraft as any).mockImplementation(async (_context: unknown, _settings: unknown, draft: { subjects: Array<{ id: string }> }) => {
      if (draft.subjects[0].id === POISON_ID) throw new Error('cannot persist');
      return { created: true, suppressed: false };
    });
  });

  it('keeps an event that keeps failing for replay, processes the others and saves the position', async () => {
    const batch = [invertedDates('1-0', 'malware-a'), invertedDates('2-0', POISON_ID), invertedDates('3-0', 'malware-b')];
    for (let attempt = 1; attempt < 5; attempt += 1) {
      await expect(curationManagerStreamHandler(batch, '3-0')).rejects.toThrow('cannot persist');
    }
    expect(redisSetManagerEventState).not.toHaveBeenCalled();
    await curationManagerStreamHandler(batch, '3-0');
    expect(redisCurationPushDeadLetters).toHaveBeenCalledWith([{ event: batch[1], replays: 0 }]);
    const persisted = (persistProposalDraft as any).mock.calls.slice(-3).map((call: any[]) => call[2].subjects[0].id);
    expect(persisted).toEqual(['malware-a', POISON_ID, 'malware-b']);
    expect(runIncrementalDuplicateDetection).not.toHaveBeenCalled();
    expect(redisSetManagerEventState).toHaveBeenCalledWith('curation_manager', '3-0');
  });

  it('saves the position of a batch processed at the first attempt without any dead letter', async () => {
    await curationManagerStreamHandler([invertedDates('4-0', 'malware-c')], '4-0');
    expect(redisCurationPushDeadLetters).not.toHaveBeenCalled();
    expect(redisSetManagerEventState).toHaveBeenCalledWith('curation_manager', '4-0');
  });
});
