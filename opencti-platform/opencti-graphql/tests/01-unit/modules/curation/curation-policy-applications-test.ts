import { beforeEach, describe, expect, it, vi } from 'vitest';
import '../../../../src/modules/index';
import { countPolicyApplications } from '../../../../src/modules/curation/curation-policies';
import { elCount } from '../../../../src/database/engine';
import { SYSTEM_USER } from '../../../../src/utils/access';
import {
  type BasicStoreEntityCurationPolicy,
  ENTITY_TYPE_CURATION_PROPOSAL,
  PROPOSAL_STATUS_AUTO_APPLIED,
  PROPOSAL_STATUS_REVERTED,
} from '../../../../src/modules/curation/curation-types';
import type { AuthContext } from '../../../../src/types/user';

vi.mock('../../../../src/database/engine', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/engine')>()),
  elCount: vi.fn(async () => 3),
}));

const context = {} as AuthContext;
const policy = { internal_id: 'policy-id' } as BasicStoreEntityCurationPolicy;

describe('counting the proposals a policy applied', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('counts the proposals that record the policy, applied or reverted since, whoever can read them', async () => {
    await expect(countPolicyApplications(context, policy)).resolves.toBe(3);
    const [, user, , options] = vi.mocked(elCount).mock.calls[0] as unknown as [AuthContext, unknown, string, { types: string[]; filters: { filters: unknown[] } }];
    expect(user).toBe(SYSTEM_USER);
    expect(options.types).toEqual([ENTITY_TYPE_CURATION_PROPOSAL]);
    expect(options.filters.filters).toEqual([
      { key: ['policy_id'], values: ['policy-id'], operator: 'eq' },
      { key: ['proposal_status'], values: [PROPOSAL_STATUS_AUTO_APPLIED, PROPOSAL_STATUS_REVERTED], operator: 'eq', mode: 'or' },
    ]);
  });
});
