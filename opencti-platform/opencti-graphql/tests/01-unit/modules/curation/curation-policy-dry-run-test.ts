import { beforeEach, describe, expect, it, vi } from 'vitest';
import { EXCLUSION_MISSING_CAPABILITY, EXCLUSION_THRESHOLD, evaluateDryRun } from '../../../../src/modules/curation/curation-policies';
import { fullEntitiesList, internalFindByIds } from '../../../../src/database/middleware-loader';
import { KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPDATE_KNMERGE, SETTINGS_SETCUSTOMIZATION } from '../../../../src/utils/access';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  fullEntitiesList: vi.fn(),
  internalFindByIds: vi.fn(),
}));
vi.mock('../../../../src/database/engine', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/engine')>()),
  elCount: vi.fn(async () => 0),
}));
vi.mock('../../../../src/database/cache', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/cache')>()),
  getEntitiesListFromCache: vi.fn(async () => []),
}));

const context = {} as AuthContext;
const policy = {
  policy_kinds: ['merge', 'stale'],
  policy_entity_types: [],
  auto_apply_threshold: 0.9,
  policy_source_class: 'any',
  forbid_open_contradiction: false,
  require_adjudication: false,
} as never;

const proposal = (id: string, kind: 'merge' | 'stale', confidence = 0.95) => ({
  internal_id: id,
  proposal_status: 'open',
  proposal_kind: kind,
  subject_types: kind === 'merge' ? ['Malware', 'Malware'] : ['Malware'],
  subject_ids: kind === 'merge' ? [`${id}-a`, `${id}-b`] : [`${id}-a`],
  confidence_score: confidence,
  recommended_action: kind === 'merge' ? 'merge' : 'revoke',
  curation_adjudication: null,
});
const proposals = [proposal('merge-1', 'merge'), proposal('stale-1', 'stale'), proposal('stale-low', 'stale', 0.6)];

const userWith = (...capabilities: string[]) => ({ id: 'user', capabilities: capabilities.map((name) => ({ name })) }) as unknown as AuthUser;

describe('curation policy dry run', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // The open proposals of the policy kinds go through the callback; the open contradictions are none.
    vi.mocked(fullEntitiesList).mockImplementation(async (_context, _user, _types, opts: any) => {
      if (opts?.callback) await opts.callback(proposals);
      return [] as never;
    });
    vi.mocked(internalFindByIds).mockImplementation(async (_context, _user, ids: any) => Object.fromEntries((ids as string[]).map((id) => [id, { internal_id: id, creator_id: ['analyst'] }])) as never);
  });

  it('counts as eligible every proposal a user with the capabilities of their actions would apply', async () => {
    const result = await evaluateDryRun(context, userWith(SETTINGS_SETCUSTOMIZATION, KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPDATE_KNMERGE), policy);
    expect(result.eligibleCount).toBe(2);
    expect(result.sampleIds).toEqual(['merge-1', 'stale-1']);
    expect(result.exclusions).toEqual({ [EXCLUSION_THRESHOLD]: 1 });
  });

  it('excludes the eligible proposals whose action needs a capability the user lacks, as a manual run does', async () => {
    const result = await evaluateDryRun(context, userWith(SETTINGS_SETCUSTOMIZATION, KNOWLEDGE_KNUPDATE), policy);
    expect(result.eligibleCount).toBe(1);
    expect(result.sampleIds).toEqual(['stale-1']);
    expect(result.impact).toEqual({ 'stale:Malware': 1 });
    // The policy reason comes first: a proposal below the threshold is not counted as a missing capability.
    expect(result.exclusions).toEqual({ [EXCLUSION_THRESHOLD]: 1, [EXCLUSION_MISSING_CAPABILITY]: 1 });
  });

  it('excludes every eligible proposal for a user who can only manage the policies', async () => {
    const result = await evaluateDryRun(context, userWith(SETTINGS_SETCUSTOMIZATION), policy);
    expect(result.eligibleCount).toBe(0);
    expect(result.exclusions).toEqual({ [EXCLUSION_THRESHOLD]: 1, [EXCLUSION_MISSING_CAPABILITY]: 2 });
  });
});
