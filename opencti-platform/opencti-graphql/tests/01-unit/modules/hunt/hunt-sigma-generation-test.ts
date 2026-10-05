import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { storeLoadById } from '../../../../src/database/middleware-loader';
import { publishUserAction } from '../../../../src/listener/UserActionListener';
import { generateHuntSigmaRule } from '../../../../src/modules/hunt/hunt-domain';
import { findByIds } from '../../../../src/modules/hunt/hunt-loaders';
import { callXtmAgent, isXtmOneConfigured } from '../../../../src/modules/playbook/components/ai-agent-shared';
import xtmOneClient from '../../../../src/modules/xtm/one/xtm-one-client';
import type { BasicStoreEntity } from '../../../../src/types/store';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';

vi.mock('../../../../src/enterprise-edition/ee', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/enterprise-edition/ee')>(),
  checkEnterpriseEdition: vi.fn().mockResolvedValue(undefined),
}));
vi.mock('../../../../src/modules/playbook/components/ai-agent-shared', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/modules/playbook/components/ai-agent-shared')>(),
  callXtmAgent: vi.fn(),
  isXtmOneConfigured: vi.fn(),
  resolveAgentJwtUser: vi.fn().mockResolvedValue({ id: 'analyst-1', user_email: 'analyst@example.com' }),
}));
vi.mock('../../../../src/modules/xtm/one/xtm-one-client', async (importOriginal) => {
  const original = await importOriginal<typeof import('../../../../src/modules/xtm/one/xtm-one-client')>();
  return { ...original, default: { ...original.default, listAgentsForIntent: vi.fn() } };
});
vi.mock('../../../../src/modules/hunt/huntRun/huntRun-domain', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/modules/hunt/huntRun/huntRun-domain')>(),
  findHuntConnectors: vi.fn().mockResolvedValue([]),
}));
vi.mock('../../../../src/modules/hunt/hunt-loaders', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/modules/hunt/hunt-loaders')>(),
  findByIds: vi.fn(),
}));
vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/middleware-loader')>(),
  storeLoadById: vi.fn(),
}));
vi.mock('../../../../src/listener/UserActionListener', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/listener/UserActionListener')>(),
  publishUserAction: vi.fn(),
}));

const SIGMA = 'title: Encoded PowerShell\nlogsource:\n  product: windows\n  category: process_creation\ndetection:\n  selection:\n    CommandLine|contains: \' -enc \'\n  condition: selection\nlevel: high\n';

const plannerAnswer = (overrides: Record<string, unknown> = {}) => JSON.stringify({
  name: 'APT-X encoded PowerShell',
  hypothesis: 'If APT-X is active, PowerShell runs an encoded command',
  hunt_type: 'telemetry',
  sigma_rule: SIGMA,
  native_queries: [],
  technique_ids: ['T1059.001'],
  target_ids: ['threat-1'],
  rationale: 'APT-X runs encoded PowerShell',
  ...overrides,
});

const threat = { internal_id: 'threat-1', standard_id: 'intrusion-set--1', entity_type: 'Intrusion-Set', name: 'APT-X' } as unknown as BasicStoreEntity;

const sentRequest = () => JSON.parse(vi.mocked(callXtmAgent).mock.calls[0][1]);

describe('Sigma rule generation of a hunt with XTM One', () => {
  beforeEach(() => {
    vi.mocked(isXtmOneConfigured).mockReturnValue(true);
    vi.mocked(xtmOneClient.listAgentsForIntent).mockResolvedValue([{ agent_slug: 'opencti-hunt-planner', priority: 0 }] as Awaited<ReturnType<typeof xtmOneClient.listAgentsForIntent>>);
    vi.mocked(findByIds).mockResolvedValue([threat]);
  });
  afterEach(() => {
    vi.mocked(callXtmAgent).mockReset();
    vi.mocked(publishUserAction).mockReset();
    vi.mocked(storeLoadById).mockReset();
  });

  it('should ask the agent of the Sigma generation intent and return the checked rule', async () => {
    vi.mocked(callXtmAgent).mockResolvedValue(plannerAnswer());
    const generation = await generateHuntSigmaRule(testContext, ADMIN_USER, {
      name: 'APT-X encoded PowerShell',
      hypothesis: 'If APT-X is active, PowerShell runs an encoded command',
      sigma_rule: 'title: draft',
      target_ids: ['threat-1'],
    });
    expect(vi.mocked(xtmOneClient.listAgentsForIntent).mock.calls[0][1]).toBe('cti.hunt_sigma_generation');
    expect(vi.mocked(callXtmAgent).mock.calls[0][0]).toBe('opencti-hunt-planner');
    const request = sentRequest();
    expect(request.task).toBe('hunt_sigma_generation');
    expect(request.hunt).toEqual({ name: 'APT-X encoded PowerShell', hypothesis: 'If APT-X is active, PowerShell runs an encoded command', current_sigma_rule: 'title: draft' });
    expect(request.threats.map((t: { id: string }) => t.id)).toEqual(['threat-1']);
    expect(generation.sigma_rule).toBe(SIGMA.trim());
    expect(generation.validation.valid).toBe(true);
    expect(generation.technique_ids).toEqual(['T1059.001']);
    // Nothing is saved, but the call is audited
    expect(vi.mocked(publishUserAction)).toHaveBeenCalledTimes(1);
    expect(vi.mocked(publishUserAction).mock.calls[0][0]).toMatchObject({ event_scope: 'create', context_data: { entity_type: 'Hunt' } });
  });

  it('should complete the request from the saved hunt', async () => {
    vi.mocked(callXtmAgent).mockResolvedValue(plannerAnswer());
    vi.mocked(storeLoadById).mockResolvedValue({
      internal_id: 'hunt-1',
      entity_type: 'Hunt',
      name: 'Saved hunt',
      hypothesis: 'Saved hypothesis of the hunt',
      sigma_rule: SIGMA,
      benign_patterns: ['backup service'],
      'hunt-target': ['threat-1'],
    } as unknown as BasicStoreEntity);
    await generateHuntSigmaRule(testContext, ADMIN_USER, { hunt_id: 'hunt-1' });
    const request = sentRequest();
    expect(request.hunt).toEqual({ name: 'Saved hunt', hypothesis: 'Saved hypothesis of the hunt', current_sigma_rule: SIGMA.trim() });
    expect(request.benign_patterns).toEqual(['backup service']);
    expect(vi.mocked(publishUserAction).mock.calls[0][0]).toMatchObject({ event_scope: 'update', context_data: { id: 'hunt-1' } });
  });

  it('should not call XTM One without a hypothesis, a threat or a technique', async () => {
    await expect(generateHuntSigmaRule(testContext, ADMIN_USER, { name: 'Empty', hypothesis: ' ' }))
      .rejects.toThrow('generated from the hypothesis of the hunt or from its threats and techniques');
    expect(vi.mocked(callXtmAgent)).not.toHaveBeenCalled();
  });

  it('should refuse when XTM One is not configured', async () => {
    vi.mocked(isXtmOneConfigured).mockReturnValue(false);
    await expect(generateHuntSigmaRule(testContext, ADMIN_USER, { hypothesis: 'If APT-X is active' }))
      .rejects.toThrow('XTM One is not configured on this platform');
    expect(vi.mocked(callXtmAgent)).not.toHaveBeenCalled();
  });

  it('should refuse an answer without a Sigma rule and audit nothing', async () => {
    vi.mocked(callXtmAgent).mockResolvedValue(plannerAnswer({
      hunt_type: 'infrastructure',
      sigma_rule: '',
      native_queries: [{ platform: 'internet', language: 'internet', query: 'services.jarm.fingerprint: abc', pipeline: 'censys' }],
    }));
    await expect(generateHuntSigmaRule(testContext, ADMIN_USER, { hypothesis: 'If APT-X is active', target_ids: ['threat-1'] }))
      .rejects.toThrow('contains no Sigma rule');
    expect(vi.mocked(publishUserAction)).not.toHaveBeenCalled();
  });

  it('should pass on the reasons of an agent that refused its own answer', async () => {
    vi.mocked(callXtmAgent).mockResolvedValue(JSON.stringify({ valid: false, errors: ['hunt_type: a hunt_sigma_generation request asks for a telemetry hunt'] }));
    await expect(generateHuntSigmaRule(testContext, ADMIN_USER, { hypothesis: 'If APT-X is active' }))
      .rejects.toThrow('asks for a telemetry hunt');
  });
});
