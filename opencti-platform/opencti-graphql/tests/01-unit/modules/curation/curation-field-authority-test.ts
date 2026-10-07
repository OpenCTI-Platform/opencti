import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  creationSources,
  curationFieldAuthorityResolver,
  decideFieldAuthority,
  rankSource,
  recordedSourcesBefore,
} from '../../../../src/modules/curation/curation-field-authority';
import { AUTHORITY_SOURCE_AUTHOR, AUTHORITY_SOURCE_CONNECTOR, type FieldAuthorityRule, type FieldAuthoritySource } from '../../../../src/modules/curation/curation-types';
import { elUpdate } from '../../../../src/database/engine';
import { getCurationSettings } from '../../../../src/modules/curation/curation-settings';
import type { AuthContext, AuthUser } from '../../../../src/types/user';
import type { StoreObject } from '../../../../src/types/store';

vi.mock('../../../../src/database/engine', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/engine')>()),
  elUpdate: vi.fn(),
}));
vi.mock('../../../../src/database/cache', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/cache')>()),
  getEntitiesListFromCache: vi.fn(async () => []),
}));
vi.mock('../../../../src/modules/curation/curation-settings', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/curation/curation-settings')>()),
  getCurationSettings: vi.fn(),
}));

const MITRE: FieldAuthoritySource = { source_type: AUTHORITY_SOURCE_AUTHOR, source_id: 'identity-mitre' };
const VENDOR: FieldAuthoritySource = { source_type: AUTHORITY_SOURCE_AUTHOR, source_id: 'identity-vendor' };
const FEED: FieldAuthoritySource = { source_type: AUTHORITY_SOURCE_CONNECTOR, source_id: 'connector-feed' };
const UNKNOWN: FieldAuthoritySource = { source_type: AUTHORITY_SOURCE_AUTHOR, source_id: 'identity-unknown' };

// MITRE first, then the vendor, then the feed connector.
const RULE: FieldAuthorityRule = { entity_type: 'Intrusion-Set', attribute: 'description', sources: [MITRE, VENDOR, FEED] };

describe('curation field authority', () => {
  describe('rankSource', () => {
    it('returns the position of the source in the rule, the most authoritative first', () => {
      expect(rankSource(RULE, [MITRE])).toBe(0);
      expect(rankSource(RULE, [VENDOR])).toBe(1);
      expect(rankSource(RULE, [FEED])).toBe(2);
    });

    it('keeps the best rank when a write has several sources (an author and a connector)', () => {
      expect(rankSource(RULE, [FEED, VENDOR])).toBe(1);
    });

    it('matches on the source type and the id together', () => {
      const sameIdOtherType: FieldAuthoritySource = { source_type: AUTHORITY_SOURCE_CONNECTOR, source_id: MITRE.source_id };
      expect(rankSource(RULE, [sameIdOtherType])).toBe(Number.MAX_SAFE_INTEGER);
    });

    it('leaves sources that the rule does not list unranked', () => {
      expect(rankSource(RULE, [UNKNOWN])).toBe(Number.MAX_SAFE_INTEGER);
      expect(rankSource(RULE, [])).toBe(Number.MAX_SAFE_INTEGER);
    });
  });

  describe('decideFieldAuthority', () => {
    it('allows a more authoritative source to overwrite, whatever the confidence', () => {
      expect(decideFieldAuthority(RULE, [MITRE], [VENDOR])).toBe('allow');
      expect(decideFieldAuthority(RULE, [VENDOR], [UNKNOWN])).toBe('allow');
    });

    it('denies a less authoritative source, whatever the confidence', () => {
      expect(decideFieldAuthority(RULE, [FEED], [MITRE])).toBe('deny');
      expect(decideFieldAuthority(RULE, [UNKNOWN], [VENDOR])).toBe('deny');
    });

    it('leaves the decision to the confidence comparison for equal ranks', () => {
      expect(decideFieldAuthority(RULE, [VENDOR], [VENDOR])).toBeUndefined();
    });

    it('leaves the decision to the confidence comparison when no side is ranked', () => {
      expect(decideFieldAuthority(RULE, [UNKNOWN], [])).toBeUndefined();
      expect(decideFieldAuthority(RULE, [], [UNKNOWN])).toBeUndefined();
    });
  });

  describe('creationSources', () => {
    const connectors = [{ internal_id: 'connector-feed', connector_user_id: 'user-feed' }, { internal_id: 'connector-other', connector_user_id: 'user-other' }];

    it('credits the author and the connector that created the entity, before any recorded write', () => {
      const created = { createdBy: 'identity-vendor', creator_id: ['user-feed', 'user-other'] };
      expect(creationSources(created, connectors)).toEqual([VENDOR, FEED]);
    });

    it('lets a value created by a connector keep its rank against a less authoritative connector', () => {
      const other: FieldAuthoritySource = { source_type: AUTHORITY_SOURCE_CONNECTOR, source_id: 'connector-other' };
      const rule: FieldAuthorityRule = { ...RULE, sources: [FEED, other] };
      expect(decideFieldAuthority(rule, [other], creationSources({ creator_id: 'user-feed' }, connectors))).toBe('deny');
    });

    it('credits nobody for an entity created by a user who is no connector and has no author', () => {
      expect(creationSources({ creator_id: ['user-analyst'] }, connectors)).toEqual([]);
    });
  });

  describe('recordedSourcesBefore', () => {
    const element = (updatedAt: string) => ({
      createdBy: 'identity-mitre',
      i_field_authority: [{ attribute: 'description', source_type: AUTHORITY_SOURCE_AUTHOR, source_id: 'identity-vendor', updated_at: updatedAt }],
    }) as unknown as StoreObject;

    it('gives the source recorded before the update', () => {
      expect(recordedSourcesBefore(element('2026-07-01T00:00:00.000Z'), 'description', [], '2026-07-02T00:00:00.000Z')).toEqual([VENDOR]);
    });

    it('gives no source when the record is the one of the update itself', () => {
      expect(recordedSourcesBefore(element('2026-07-02T00:00:00.050Z'), 'description', [], '2026-07-02T00:00:00.000Z')).toEqual([]);
    });

    it('gives the recorded source when the time of the update is unknown, and the creation sources without a record', () => {
      expect(recordedSourcesBefore(element('2026-07-02T00:00:00.050Z'), 'description', [])).toEqual([VENDOR]);
      expect(recordedSourcesBefore(element('2026-07-02T00:00:00.050Z'), 'name', [], '2026-07-02T00:00:00.000Z')).toEqual([MITRE]);
    });
  });

  describe('recordApplied', () => {
    const context = {} as AuthContext;
    const analyst = { id: 'user-analyst' } as AuthUser;
    const element = { _index: 'index', internal_id: 'element-id' } as unknown as StoreObject;
    const record = (patch: Record<string, unknown>, keys: string[], ctx = context) => curationFieldAuthorityResolver.recordApplied(ctx, analyst, element, 'Intrusion-Set', patch, keys);
    const recorded = () => (vi.mocked(elUpdate).mock.calls[0][3] as { script: { params: { entries: unknown[] } } }).script.params.entries;

    beforeEach(() => {
      vi.clearAllMocks();
      vi.mocked(getCurationSettings).mockResolvedValue({ field_authority_enabled: true, field_authority_rules: [RULE] } as never);
    });

    it('records the source the rule ranks for an applied attribute', async () => {
      await record({ createdBy: VENDOR.source_id }, ['description']);
      expect(recorded()).toEqual([expect.objectContaining({ attribute: 'description', ...VENDOR })]);
    });

    it('records a writer the rule does not rank, so the source recorded before is never taken for it', async () => {
      await record({ createdBy: UNKNOWN.source_id }, ['description']);
      expect(recorded()).toEqual([expect.objectContaining({ attribute: 'description', ...UNKNOWN })]);
      vi.mocked(elUpdate).mockClear();
      await record({}, ['description']);
      expect(recorded()).toEqual([expect.objectContaining({ attribute: 'description', source_type: 'unranked' })]);
      expect(rankSource(RULE, recorded() as FieldAuthoritySource[])).toBe(Number.MAX_SAFE_INTEGER);
    });

    it('records nothing for an attribute without a rule, or for a synchronized upsert', async () => {
      await record({ createdBy: VENDOR.source_id }, ['name']);
      await record({ createdBy: VENDOR.source_id }, ['description'], { synchronizedUpsert: true } as unknown as AuthContext);
      expect(elUpdate).not.toHaveBeenCalled();
    });
  });

  describe('an upsert writing a ruled attribute through its upsert operations', () => {
    const context = {} as AuthContext;
    const writer = { id: 'user-writer' } as AuthUser;
    const element = { internal_id: 'element-id', createdBy: MITRE.source_id } as unknown as StoreObject;
    const operations = { createdBy: FEED.source_id, upsertOperations: [{ key: 'description', value: ['Rewritten'], operation: 'replace' }] };

    beforeEach(() => {
      vi.clearAllMocks();
      vi.mocked(getCurationSettings).mockResolvedValue({ field_authority_enabled: true, field_authority_rules: [RULE] } as never);
    });

    it('is governed and decided like a patch key', async () => {
      expect(await curationFieldAuthorityResolver.governs(context, 'Intrusion-Set', operations)).toBe(true);
      const decisions = await curationFieldAuthorityResolver.resolve(context, writer, element, 'Intrusion-Set', operations);
      // An author the rule ranks below MITRE, the author of the current value.
      expect(decisions.get('description')).toBe('deny');
    });

    it('is not governed for an attribute without a rule', async () => {
      const other = { upsertOperations: [{ key: 'name', value: ['Other'], operation: 'replace' }] };
      expect(await curationFieldAuthorityResolver.governs(context, 'Intrusion-Set', other)).toBe(false);
    });
  });
});
