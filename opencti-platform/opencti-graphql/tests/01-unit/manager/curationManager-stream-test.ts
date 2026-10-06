import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { creatorsBeforeUpdate, curationManagerStreamHandler, isNamePatchPath, replayDeadLetters } from '../../../src/manager/curationManager';
import {
  redisCurationClaimDeadLetters,
  redisCurationPushDeadLetters,
  redisCurationSettleDeadLetter,
  redisCurationSwapFieldWriter,
  redisSetManagerEventState,
} from '../../../src/database/redis';
import type { AuthContext } from '../../../src/types/user';
import type { CurationSettings } from '../../../src/modules/curation/curation-types';
import { persistProposalDraft } from '../../../src/modules/curation/curation-proposals';
import { runIncrementalDuplicateDetection } from '../../../src/modules/curation/curation-scan';
import { getCurationSettings } from '../../../src/modules/curation/curation-settings';
import { AUTHORITY_SOURCE_CONNECTOR } from '../../../src/modules/curation/curation-types';
import { storeLoadById } from '../../../src/database/middleware-loader';
import { schemaAttributesDefinition } from '../../../src/schema/schema-attributes';
import type { DataEvent, SseEvent, UpdateEvent } from '../../../src/types/event';

vi.mock('../../../src/manager/managerModule', () => ({ registerManager: vi.fn() }));

vi.mock('../../../src/database/redis', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/database/redis')>()),
  redisCurationPushDeadLetters: vi.fn(),
  redisCurationClaimDeadLetters: vi.fn(async () => []),
  redisCurationSettleDeadLetter: vi.fn(),
  redisCurationSwapFieldWriter: vi.fn(async () => ({ previous: null, replayed: false })),
  redisGetManagerEventState: vi.fn(),
  redisSetManagerEventState: vi.fn(),
}));

vi.mock('../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/database/middleware-loader')>()),
  internalFindByIds: vi.fn(async () => [{ internal_id: 'uses-1', fromId: 'intrusion-set-1', toId: 'attack-pattern-1', fromName: 'APT-X', toName: 'Phishing' }]),
  storeLoadById: vi.fn(async () => undefined),
}));

// The only connector of the platform: the feed whose user writes as that connector.
vi.mock('../../../src/database/cache', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/database/cache')>()),
  getEntitiesListFromCache: vi.fn(async () => [{ internal_id: 'connector-feed', connector_user_id: 'feed-user' }]),
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

  it('recognizes the patches that change the names of an entity, wherever its type holds its aliases', () => {
    const extension = 'extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba';
    expect(isNamePatchPath('/name')).toBe(true);
    expect(isNamePatchPath('/aliases/0')).toBe(true);
    expect(isNamePatchPath('/x_opencti_aliases')).toBe(true);
    expect(isNamePatchPath(`/extensions/${extension}/aliases/1`)).toBe(true);
    expect(isNamePatchPath('/description')).toBe(true);
    expect(isNamePatchPath(`/extensions/${extension}/score`)).toBe(false);
    expect(isNamePatchPath('/names_count')).toBe(false);
    expect(isNamePatchPath(undefined)).toBe(false);
  });

  it('saves the position of a batch processed at the first attempt without any dead letter', async () => {
    await curationManagerStreamHandler([invertedDates('4-0', 'malware-c')], '4-0');
    expect(redisCurationPushDeadLetters).not.toHaveBeenCalled();
    expect(redisSetManagerEventState).toHaveBeenCalledWith('curation_manager', '4-0');
  });
});

describe('Curation manager dead letters', () => {
  const settings = { curation_enabled: true, curated_entity_types: [], enabled_detectors: ['contradiction'] } as unknown as CurationSettings;
  const replay = (eventId: string, entityId: string, replays: number) => ({ event: invertedDates(eventId, entityId), replays });

  beforeEach(() => {
    vi.clearAllMocks();
    (persistProposalDraft as any).mockImplementation(async (_context: unknown, _settings: unknown, draft: { subjects: Array<{ id: string }> }) => {
      if (draft.subjects[0].id === POISON_ID) throw new Error('cannot persist');
      return { created: true, suppressed: false };
    });
  });

  it('settles each replayed event once handled, and puts back the one that fails again with its replay count', async () => {
    const handled = replay('11-0', 'malware-d', 2);
    const failing = replay('12-0', POISON_ID, 3);
    vi.mocked(redisCurationClaimDeadLetters).mockResolvedValueOnce([{ raw: 'handled', entry: handled }, { raw: 'failing', entry: failing }]);
    await replayDeadLetters({} as AuthContext, settings);
    expect(redisCurationSettleDeadLetter).toHaveBeenNthCalledWith(1, 'handled', null);
    expect(redisCurationSettleDeadLetter).toHaveBeenNthCalledWith(2, 'failing', { ...failing, replays: 4 });
    expect(redisCurationPushDeadLetters).not.toHaveBeenCalled();
  });

  it('drops an event whose last replay failed', async () => {
    vi.mocked(redisCurationClaimDeadLetters).mockResolvedValueOnce([{ raw: 'last', entry: replay('13-0', POISON_ID, 9) }]);
    await replayDeadLetters({} as AuthContext, settings);
    expect(redisCurationSettleDeadLetter).toHaveBeenCalledWith('last', null);
  });
});

const EXTENSION = 'extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba';
const FIRST_PROCEDURE = 'Uses a watering hole on industry forums to deliver the implant';
const SECOND_PROCEDURE = 'Sends spearphishing attachments with macro-enabled documents';

const usesEvent = (eventId: string, type: 'create' | 'update', writer: string, creators: string[], context?: unknown) => ({
  id: eventId,
  event: type,
  data: {
    type,
    origin: { user_id: writer },
    data: {
      description: type === 'create' ? FIRST_PROCEDURE : SECOND_PROCEDURE,
      extensions: { [EXTENSION]: { id: 'uses-1', type: 'uses', target_type: 'Attack-Pattern', creator_ids: creators } },
    },
    ...(context ? { context } : {}),
  },
}) as unknown as SseEvent<DataEvent>;

// An upsert by connector B replacing the procedure of connector A: B joins the creators in the same event.
const overwriteByNewSource = () => usesEvent('6-0', 'update', 'connector-b', ['connector-a', 'connector-b'], {
  patch: [{ op: 'replace', path: '/description', value: SECOND_PROCEDURE }, { op: 'add', path: `/extensions/${EXTENSION}/creator_ids/1`, value: 'connector-b' }],
  reverse_patch: [{ op: 'replace', path: '/description', value: FIRST_PROCEDURE }, { op: 'remove', path: `/extensions/${EXTENSION}/creator_ids/1` }],
});

describe('Curation manager procedure conflicts', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(getCurationSettings).mockResolvedValue({ curation_enabled: true, curated_entity_types: [], enabled_detectors: ['relationship_conflict'] } as never);
    (persistProposalDraft as any).mockResolvedValue({ created: true, suppressed: false });
  });

  it('reads the creators an element had before an update', () => {
    expect(creatorsBeforeUpdate(overwriteByNewSource().data as UpdateEvent)).toEqual(['connector-a']);
    const unchanged = usesEvent('7-0', 'update', 'connector-b', ['connector-a', 'connector-b'], { patch: [], reverse_patch: [] });
    expect(creatorsBeforeUpdate(unchanged.data as UpdateEvent)).toEqual(['connector-a', 'connector-b']);
  });

  it('remembers the writer of the procedure a relationship is created with', async () => {
    await curationManagerStreamHandler([usesEvent('5-0', 'create', 'connector-a', ['connector-a'])], '5-0');
    expect(redisCurationSwapFieldWriter).toHaveBeenCalledWith('uses-1', 'description', 'connector-a', '5-0', expect.any(Number));
    expect(persistProposalDraft).not.toHaveBeenCalled();
  });

  it('detects the first overwrite of a procedure by a new source, before any writer is remembered', async () => {
    await curationManagerStreamHandler([overwriteByNewSource()], '6-0');
    const draft = (persistProposalDraft as any).mock.calls[0][2];
    expect(draft.kind).toBe('relationship_conflict');
    expect(draft.action_payload.previous).toEqual({ text: FIRST_PROCEDURE, source_id: 'connector-a' });
    expect(draft.action_payload.current).toEqual({ text: SECOND_PROCEDURE, source_id: 'connector-b' });
  });

  it('raises nothing when the writer was already a creator and no other writer is remembered', async () => {
    const ownText = usesEvent('8-0', 'update', 'connector-b', ['connector-a', 'connector-b'], {
      patch: [{ op: 'replace', path: '/description', value: SECOND_PROCEDURE }],
      reverse_patch: [{ op: 'replace', path: '/description', value: FIRST_PROCEDURE }],
    });
    await curationManagerStreamHandler([ownText], '8-0');
    expect(persistProposalDraft).not.toHaveBeenCalled();
  });
});

const FEED_DESCRIPTION = 'Espionage group tracked by the vendor feed since 2014';
const EDITED_DESCRIPTION = 'Edited by hand';

const descriptionEdit = (eventId: string, writer: string) => ({
  id: eventId,
  event: 'update',
  data: {
    type: 'update',
    origin: { user_id: writer },
    data: { name: 'APT-X', description: EDITED_DESCRIPTION, extensions: { [EXTENSION]: { id: 'intrusion-set-1', type: 'Intrusion-Set' } } },
    context: {
      patch: [{ op: 'replace', path: '/description', value: EDITED_DESCRIPTION }],
      reverse_patch: [{ op: 'replace', path: '/description', value: FEED_DESCRIPTION }],
    },
  },
}) as unknown as SseEvent<DataEvent>;

describe('Curation manager field precedence', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(getCurationSettings).mockResolvedValue({
      curation_enabled: true,
      curated_entity_types: ['Intrusion-Set'],
      enabled_detectors: [],
      field_authority_enabled: true,
      field_authority_rules: [{ entity_type: 'Intrusion-Set', attribute: 'description', sources: [{ source_type: AUTHORITY_SOURCE_CONNECTOR, source_id: 'connector-feed' }] }],
    } as never);
    (persistProposalDraft as any).mockResolvedValue({ created: true, suppressed: false });
    // The feed wrote the description more than 30 days ago: its writer is no longer remembered, its authority is recorded.
    vi.mocked(storeLoadById).mockResolvedValue({
      internal_id: 'intrusion-set-1',
      i_field_authority: [{ attribute: 'description', source_type: AUTHORITY_SOURCE_CONNECTOR, source_id: 'connector-feed', updated_at: '2026-07-01T00:00:00.000Z' }],
    } as never);
    vi.spyOn(schemaAttributesDefinition, 'getAttribute').mockReturnValue({ name: 'description' } as never);
  });

  afterEach(() => {
    vi.mocked(schemaAttributesDefinition.getAttribute).mockRestore();
  });

  it('proposes to restore a value of an authoritative source overwritten once its writer is no longer remembered', async () => {
    await curationManagerStreamHandler([descriptionEdit('20-0', 'analyst-user')], '20-0');
    expect(storeLoadById).toHaveBeenCalledWith(expect.anything(), expect.anything(), 'intrusion-set-1', 'Intrusion-Set');
    const draft = (persistProposalDraft as any).mock.calls[0][2];
    expect(draft.kind).toBe('field_precedence');
    expect(draft.action_payload).toEqual({ element_id: 'intrusion-set-1', key: 'description', value: FEED_DESCRIPTION, overwritten_value: EDITED_DESCRIPTION });
  });

  it('proposes nothing when the recorded source writes the field again', async () => {
    await curationManagerStreamHandler([descriptionEdit('21-0', 'feed-user')], '21-0');
    expect(persistProposalDraft).not.toHaveBeenCalled();
  });
});
