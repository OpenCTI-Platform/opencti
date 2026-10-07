import { beforeEach, describe, expect, it, vi } from 'vitest';
import '../../../../src/modules/index';
import { adjudicateProposal, resolveAdjudicationRunAs } from '../../../../src/modules/curation/curation-adjudication';
import { getEntitiesMapFromCache } from '../../../../src/database/cache';
import { storeLoadById } from '../../../../src/database/middleware-loader';
import { patchAttribute, storeLoadByIdsWithRefs } from '../../../../src/database/middleware';
import { redisCurationReserveCounter } from '../../../../src/database/redis';
import { callXtmAgent } from '../../../../src/modules/playbook/components/ai-agent-shared';
import { OPENCTI_ADMIN_UUID } from '../../../../src/schema/general';
import { CURATION_MANAGER_USER } from '../../../../src/utils/access';
import { type BasicStoreEntityCurationProposal, type CurationSettings, PROPOSAL_KIND_MERGE, PROPOSAL_STATUS_OPEN } from '../../../../src/modules/curation/curation-types';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

vi.mock('../../../../src/database/cache', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/cache')>()),
  getEntitiesMapFromCache: vi.fn(),
}));
vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  storeLoadById: vi.fn(),
}));
vi.mock('../../../../src/database/middleware', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware')>()),
  storeLoadByIdsWithRefs: vi.fn(),
  patchAttribute: vi.fn(),
}));
vi.mock('../../../../src/database/redis', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/redis')>()),
  redisCurationReserveCounter: vi.fn(async () => true),
}));
vi.mock('../../../../src/enterprise-edition/ee', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/enterprise-edition/ee')>()),
  checkEnterpriseEdition: vi.fn(async () => undefined),
}));
vi.mock('../../../../src/modules/playbook/components/ai-agent-shared', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/playbook/components/ai-agent-shared')>()),
  isXtmOneConfigured: () => true,
  buildPlaybookAutomationContext: () => ({}),
  callXtmAgent: vi.fn(),
}));
vi.mock('../../../../src/modules/xtm/one/xtm-one-client', () => ({
  default: { listAgentsForIntent: vi.fn(async () => [{ agent_slug: 'opencti-curator', agent_name: 'OpenCTI Curator', priority: 10 }]) },
}));
vi.mock('../../../../src/listener/UserActionListener', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/listener/UserActionListener')>()),
  publishUserAction: vi.fn(async () => undefined),
}));
vi.mock('../../../../src/modules/curation/curation-locks', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/curation/curation-locks')>()),
  withProposalAdjudicationLock: (_id: string, fn: () => Promise<unknown>) => fn(),
  withProposalTransitionLock: (_id: string, fn: () => Promise<unknown>) => fn(),
}));

const context = {} as AuthContext;
const account = (id: string, overrides: Partial<AuthUser> = {}) => ({
  id,
  internal_id: id,
  user_email: `${id}@example.com`,
  account_status: 'Active',
  capabilities: [{ name: 'KNOWLEDGE' }],
  ...overrides,
} as unknown as AuthUser);
const admin = account(OPENCTI_ADMIN_UUID, { capabilities: [{ name: 'BYPASS' }] } as Partial<AuthUser>);
const platformUsers = (...users: AuthUser[]) => new Map(users.map((user) => [user.id, user]));
const settingsWith = (runAsId: string | null) => ({ adjudication_run_as_id: runAsId, adjudication_agent_slug: null, adjudication_daily_limit: 50 }) as unknown as CurationSettings;

describe('the account adjudication runs as', () => {
  it('is the platform administrator when the settings name none', async () => {
    vi.mocked(getEntitiesMapFromCache).mockResolvedValue(platformUsers(admin) as never);
    await expect(resolveAdjudicationRunAs(context, settingsWith(null))).resolves.toBe(admin);
  });

  it('is the selected account when it is active and has Access knowledge', async () => {
    const analyst = account('analyst-id');
    vi.mocked(getEntitiesMapFromCache).mockResolvedValue(platformUsers(admin, analyst) as never);
    await expect(resolveAdjudicationRunAs(context, settingsWith('analyst-id'))).resolves.toBe(analyst);
  });

  it('never falls back to the administrator when the selected account cannot adjudicate', async () => {
    const disabled = account('disabled-id', { account_status: 'Inactive' } as Partial<AuthUser>);
    const reader = account('reader-id', { capabilities: [{ name: 'EXPLORE' }] } as Partial<AuthUser>);
    vi.mocked(getEntitiesMapFromCache).mockResolvedValue(platformUsers(admin, disabled, reader) as never);
    await expect(resolveAdjudicationRunAs(context, settingsWith('deleted-id'))).rejects.toThrow('The Run as account of the curation settings');
    await expect(resolveAdjudicationRunAs(context, settingsWith('disabled-id'))).rejects.toThrow('The Run as account of the curation settings');
    await expect(resolveAdjudicationRunAs(context, settingsWith('reader-id'))).rejects.toThrow('The Run as account of the curation settings');
  });
});

describe('a proposal sent for adjudication', () => {
  const analyst = account('analyst-id');
  const proposal = {
    internal_id: 'proposal-id',
    name: 'Shadow Lynx duplicates',
    proposal_kind: PROPOSAL_KIND_MERGE,
    proposal_status: PROPOSAL_STATUS_OPEN,
    in_ambiguous_band: true,
    subject_ids: ['set-a', 'set-b'],
  } as unknown as BasicStoreEntityCurationProposal;

  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(getEntitiesMapFromCache).mockResolvedValue(platformUsers(admin, analyst) as never);
    vi.mocked(storeLoadById).mockResolvedValue(proposal as never);
  });

  it('is not sent when the Run as account cannot read every subject, and spends no budget', async () => {
    vi.mocked(storeLoadByIdsWithRefs).mockResolvedValue([{ internal_id: 'set-a', entity_type: 'Intrusion-Set', name: 'Shadow Lynx' }] as never);
    await expect(adjudicateProposal(context, CURATION_MANAGER_USER, proposal, settingsWith('analyst-id'))).resolves.toBeNull();
    expect(storeLoadByIdsWithRefs).toHaveBeenCalledWith(context, analyst, ['set-a', 'set-b']);
    expect(redisCurationReserveCounter).not.toHaveBeenCalled();
    expect(callXtmAgent).not.toHaveBeenCalled();
  });

  it('is refused without calling the agent once the daily budget is spent', async () => {
    vi.mocked(storeLoadByIdsWithRefs).mockResolvedValue([
      { internal_id: 'set-a', entity_type: 'Intrusion-Set', name: 'Shadow Lynx' },
      { internal_id: 'set-b', entity_type: 'Intrusion-Set', name: 'Shadow Lynx Group' },
    ] as never);
    vi.mocked(redisCurationReserveCounter).mockResolvedValueOnce(false);
    await expect(adjudicateProposal(context, CURATION_MANAGER_USER, proposal, settingsWith('analyst-id'))).rejects.toThrow('The daily adjudication budget is exhausted');
    expect(redisCurationReserveCounter).toHaveBeenCalledWith('adjudication', new Date().toISOString().slice(0, 10), 50);
    expect(callXtmAgent).not.toHaveBeenCalled();
  });

  it('is not sent when the Run as account cannot read the proposal', async () => {
    vi.mocked(storeLoadById).mockImplementation(async (_context, user) => (user === analyst ? undefined : proposal) as never);
    await expect(adjudicateProposal(context, CURATION_MANAGER_USER, proposal, settingsWith('analyst-id'))).resolves.toBeNull();
    expect(storeLoadByIdsWithRefs).not.toHaveBeenCalled();
    expect(callXtmAgent).not.toHaveBeenCalled();
  });

  describe('when the agent answers', () => {
    const answer = JSON.stringify({ decision: 'merge', rationale: 'Same infrastructure and victims.', target_id: 'set-a' });
    const recordedPatches = () => vi.mocked(patchAttribute).mock.calls.map(([, , , , patch]) => patch as Record<string, unknown>)
      .filter((patch) => patch.curation_adjudication !== undefined);

    beforeEach(() => {
      vi.mocked(storeLoadByIdsWithRefs).mockResolvedValue([
        { internal_id: 'set-a', entity_type: 'Intrusion-Set', name: 'Shadow Lynx' },
        { internal_id: 'set-b', entity_type: 'Intrusion-Set', name: 'Shadow Lynx Group' },
      ] as never);
      vi.mocked(patchAttribute).mockImplementation(async (_context, _user, _id, _type, patch) => ({ element: { ...proposal, ...patch } }) as never);
    });

    it('records the answer on a proposal nobody decided during the call', async () => {
      vi.mocked(callXtmAgent).mockResolvedValue(answer as never);
      const adjudicated = await adjudicateProposal(context, CURATION_MANAGER_USER, proposal, settingsWith('analyst-id'));
      expect(recordedPatches()).toEqual([expect.objectContaining({ target_id: 'set-a', curation_adjudication: expect.objectContaining({ decision: 'merge', verified: true }) })]);
      expect(adjudicated?.curation_adjudication?.decision).toBe('merge');
    });

    it('discards the answer when a decision was recorded on the open proposal during the call', async () => {
      const manual = { decision: 'distinct', rationale: 'Two distinct sets.', agent_slug: null, model: null, adjudicated_at: '2026-10-07T12:30:00.000Z', applied: false, verified: false };
      let decided = false;
      vi.mocked(storeLoadById).mockImplementation(async () => (decided ? { ...proposal, curation_adjudication: manual, target_id: 'set-b' } : proposal) as never);
      vi.mocked(callXtmAgent).mockImplementation(async () => {
        decided = true;
        return answer as never;
      });
      const adjudicated = await adjudicateProposal(context, CURATION_MANAGER_USER, proposal, settingsWith('analyst-id'));
      expect(callXtmAgent).toHaveBeenCalledTimes(1);
      expect(recordedPatches()).toEqual([]);
      expect(adjudicated?.curation_adjudication).toEqual(manual);
      expect(adjudicated?.target_id).toBe('set-b');
    });
  });
});
