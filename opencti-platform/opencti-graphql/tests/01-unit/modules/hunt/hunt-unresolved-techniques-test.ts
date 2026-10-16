import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fullEntitiesList } from '../../../../src/database/middleware-loader';
import { createEntity } from '../../../../src/database/middleware';
import { resolveHuntConnectorTargets } from '../../../../src/modules/hunt/hunt-dispatch';
import { updateHuntRunInformation } from '../../../../src/modules/hunt/hunt-stats';
import { findUnresolvedHuntTechniques } from '../../../../src/modules/hunt/hunt-logic';
import { validateSigmaRule } from '../../../../src/modules/hunt/hunt-sigma';
import huntResolvers from '../../../../src/modules/hunt/hunt-resolvers';
import { createHuntRuns } from '../../../../src/modules/hunt/huntRun/huntRun-domain';
import type { BasicStoreEntityHunt } from '../../../../src/modules/hunt/hunt-types';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/middleware-loader')>(),
  fullEntitiesList: vi.fn(),
}));

vi.mock('../../../../src/database/middleware', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/middleware')>(),
  createEntity: vi.fn(),
}));

vi.mock('../../../../src/modules/hunt/hunt-dispatch', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/modules/hunt/hunt-dispatch')>(),
  resolveHuntConnectorTargets: vi.fn(),
}));

vi.mock('../../../../src/modules/hunt/hunt-stats', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/modules/hunt/hunt-stats')>(),
  updateHuntRunInformation: vi.fn(),
}));

const SIGMA_RULE = [
  'title: Encoded PowerShell',
  'logsource:',
  '  product: windows',
  '  category: process_creation',
  'detection:',
  '  selection:',
  "    CommandLine|contains: ' -enc '",
  '  condition: selection',
  'tags:',
  '  - attack.execution',
  '  - attack.t1059.001',
  '  - attack.t9999',
].join('\n');

const hunt = {
  internal_id: 'hunt-1',
  name: 'Encoded PowerShell',
  hunt_type: 'sigma',
  hunt_status: 'active',
  sigma_rule: SIGMA_RULE,
  escalation_threshold: 10,
  time_window_hours: 24,
} as unknown as BasicStoreEntityHunt;

// The knowledge base holds T1059.001 only
const knowledgeBase = () => vi.mocked(fullEntitiesList).mockResolvedValue([{ internal_id: 'attack-1', x_mitre_id: 'T1059.001' }] as never);

describe('Tagged techniques the knowledge base lacks', () => {
  beforeEach(() => {
    vi.mocked(resolveHuntConnectorTargets).mockResolvedValue([
      { connector: { internal_id: 'connector-1', name: 'Splunk Hunt' }, securityPlatform: { internal_id: 'platform-1', name: 'Splunk' } },
    ] as never);
    vi.mocked(createEntity).mockImplementation(async (_context, _user, input) => ({ ...input, internal_id: 'run-1' }) as never);
    vi.mocked(updateHuntRunInformation).mockResolvedValue(undefined as never);
  });

  afterEach(() => {
    vi.mocked(fullEntitiesList).mockReset();
    vi.mocked(createEntity).mockReset();
  });

  it('should name the tagged techniques no attack pattern matches', async () => {
    knowledgeBase();
    expect(await findUnresolvedHuntTechniques(testContext, ADMIN_USER, SIGMA_RULE)).toEqual(['T9999']);
    expect(await findUnresolvedHuntTechniques(testContext, ADMIN_USER, null)).toEqual([]);
  });

  it('should report them on the Sigma validation the hunt form and the hunt page read', async () => {
    knowledgeBase();
    const resolver = (huntResolvers.HuntSigmaValidation as Record<string, (...args: unknown[]) => Promise<string[]>>).unresolved_attack_techniques;
    const unresolved = await resolver(validateSigmaRule(SIGMA_RULE), {}, { ...testContext, user: ADMIN_USER });
    expect(unresolved).toEqual(['T9999']);
  });

  it('should record them on every executed run, never on a translation preview', async () => {
    knowledgeBase();
    await createHuntRuns(testContext, hunt, { trigger: 'manual', requester: ADMIN_USER, dispatch: false });
    expect((vi.mocked(createEntity).mock.calls.at(-1)?.[2] as Record<string, unknown>).unresolved_techniques).toEqual(['T9999']);
    await createHuntRuns(testContext, hunt, { trigger: 'preview', mode: 'preview', requester: ADMIN_USER, dispatch: false });
    expect((vi.mocked(createEntity).mock.calls.at(-1)?.[2] as Record<string, unknown>).unresolved_techniques).toEqual([]);
  });

  it('should still create the run when the lookup fails, reporting none', async () => {
    vi.mocked(fullEntitiesList).mockRejectedValue(new Error('Search unavailable'));
    const runs = await createHuntRuns(testContext, hunt, { trigger: 'schedule', dispatch: false });
    expect(runs).toHaveLength(1);
    expect((vi.mocked(createEntity).mock.calls.at(-1)?.[2] as Record<string, unknown>).unresolved_techniques).toEqual([]);
  });
});
