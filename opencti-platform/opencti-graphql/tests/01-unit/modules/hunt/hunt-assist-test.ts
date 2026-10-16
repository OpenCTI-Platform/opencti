import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fullEntitiesList, storeLoadById } from '../../../../src/database/middleware-loader';
import { publishUserAction } from '../../../../src/listener/UserActionListener';
import { assistHunt } from '../../../../src/modules/hunt/hunt-domain';
import { findByIds } from '../../../../src/modules/hunt/hunt-loaders';
import { callXtmAgent, isXtmOneConfigured } from '../../../../src/modules/playbook/components/ai-agent-shared';
import xtmOneClient from '../../../../src/modules/xtm/one/xtm-one-client';
import { HuntAssistField } from '../../../../src/generated/graphql';
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
  fullEntitiesList: vi.fn(),
}));
vi.mock('../../../../src/listener/UserActionListener', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/listener/UserActionListener')>(),
  publishUserAction: vi.fn(),
}));

const SIGMA = 'title: Encoded PowerShell\nlogsource:\n  product: windows\n  category: process_creation\ndetection:\n  selection:\n    CommandLine|contains: \' -enc \'\n  condition: selection\nlevel: high\n';

const plannerAnswer = (overrides: Record<string, unknown> = {}) => JSON.stringify({
  name: 'APT-X encoded PowerShell',
  description: 'Hunts the encoded PowerShell of APT-X',
  hypothesis: 'If APT-X is active, PowerShell runs an encoded command',
  hunt_type: 'telemetry',
  sigma_rule: SIGMA,
  native_queries: [],
  expected_observables: ['Process', 'StixFile'],
  benign_patterns: ['Configuration management agents'],
  technique_ids: ['T1059.001', 'T9999'],
  target_ids: ['threat-1'],
  rationale: 'APT-X runs encoded PowerShell',
  ...overrides,
});

const threat = { internal_id: 'threat-1', standard_id: 'intrusion-set--1', entity_type: 'Intrusion-Set', name: 'APT-X' } as unknown as BasicStoreEntity;
const powershell = { internal_id: 'technique-1', entity_type: 'Attack-Pattern', name: 'PowerShell', x_mitre_id: 'T1059.001' } as unknown as BasicStoreEntity;

const sentRequest = () => JSON.parse(vi.mocked(callXtmAgent).mock.calls[0][1]);

const failureOf = async (promise: Promise<unknown>) => {
  try {
    await promise;
  } catch (error) {
    return (error as { message: string; extensions: { data: { failure?: string } } });
  }
  throw new Error('The call did not fail');
};

describe('Assistance of a hunt being written with XTM One', () => {
  beforeEach(() => {
    vi.mocked(isXtmOneConfigured).mockReturnValue(true);
    vi.mocked(xtmOneClient.listAgentsForIntent).mockResolvedValue([{ agent_slug: 'opencti-hunt-planner', priority: 0 }] as Awaited<ReturnType<typeof xtmOneClient.listAgentsForIntent>>);
    vi.mocked(findByIds).mockResolvedValue([threat]);
    vi.mocked(fullEntitiesList).mockResolvedValue([powershell]);
  });
  afterEach(() => {
    vi.mocked(callXtmAgent).mockReset();
    vi.mocked(publishUserAction).mockReset();
    vi.mocked(storeLoadById).mockReset();
    vi.mocked(xtmOneClient.listAgentsForIntent).mockReset();
  });

  it('should write the Sigma rule with the Sigma generation intent and propose what the answer implies', async () => {
    vi.mocked(callXtmAgent).mockResolvedValue(plannerAnswer());
    const proposal = await assistHunt(testContext, ADMIN_USER, {
      fields: [HuntAssistField.SigmaRule],
      name: 'APT-X encoded PowerShell',
      hypothesis: 'If APT-X is active, PowerShell runs an encoded command',
      sigma_rule: 'title: draft',
      target_ids: ['threat-1'],
    });
    expect(vi.mocked(xtmOneClient.listAgentsForIntent).mock.calls[0][1]).toBe('cti.hunt_sigma_generation');
    expect(vi.mocked(callXtmAgent).mock.calls[0][0]).toBe('opencti-hunt-planner');
    const request = sentRequest();
    expect(request.task).toBe('hunt_sigma_generation');
    expect(request.hunt).toMatchObject({ name: 'APT-X encoded PowerShell', current_sigma_rule: 'title: draft', requested_fields: ['sigma_rule'] });
    expect(request.threats.map((t: { id: string }) => t.id)).toEqual(['threat-1']);
    expect(proposal.fields).toEqual(['sigma_rule']);
    expect(proposal.sigma_rule).toBe(SIGMA.trim());
    expect(proposal.sigma_validation?.valid).toBe(true);
    // The techniques the agent named are proposed when the platform knows them, the others are listed
    expect(proposal.techniques).toEqual([{ id: 'technique-1', entity_type: 'Attack-Pattern', name: 'PowerShell', x_mitre_id: 'T1059.001' }]);
    expect(proposal.unknown_technique_ids).toEqual(['T9999']);
    expect(proposal.expected_observables).toEqual(['Process', 'StixFile']);
    // Nothing is saved, but the call is audited
    expect(vi.mocked(publishUserAction)).toHaveBeenCalledTimes(1);
    expect(vi.mocked(publishUserAction).mock.calls[0][0]).toMatchObject({ event_scope: 'create', context_data: { entity_type: 'Hunt', input: { fields: ['sigma_rule'] } } });
  });

  it('should plan a whole hunt from a name alone with the planner intent', async () => {
    vi.mocked(callXtmAgent).mockResolvedValue(plannerAnswer());
    const proposal = await assistHunt(testContext, ADMIN_USER, { name: 'Encoded PowerShell', hypothesis: '', target_ids: [], technique_ids: [] });
    expect(vi.mocked(xtmOneClient.listAgentsForIntent).mock.calls[0][1]).toBe('cti.hunt_hypothesis');
    expect(sentRequest().hunt).toMatchObject({ name: 'Encoded PowerShell', hypothesis: '', requested_fields: [] });
    expect(proposal.hypothesis).toBe('If APT-X is active, PowerShell runs an encoded command');
    expect(proposal.description).toBe('Hunts the encoded PowerShell of APT-X');
    expect(proposal.benign_patterns).toEqual(['Configuration management agents']);
  });

  it('should plan from the words of the analyst on an empty form', async () => {
    vi.mocked(callXtmAgent).mockResolvedValue(plannerAnswer());
    await assistHunt(testContext, ADMIN_USER, { fields: [HuntAssistField.Hypothesis], prompt: '  Office documents launching encoded PowerShell ' });
    expect(sentRequest().hunt).toMatchObject({ analyst_request: 'Office documents launching encoded PowerShell', requested_fields: ['hypothesis'] });
  });

  it('should complete the request from the saved hunt', async () => {
    vi.mocked(callXtmAgent).mockResolvedValue(plannerAnswer());
    vi.mocked(storeLoadById).mockResolvedValue({
      internal_id: 'hunt-1',
      entity_type: 'Hunt',
      name: 'Saved hunt',
      hunt_type: 'telemetry',
      hypothesis: 'Saved hypothesis of the hunt',
      sigma_rule: SIGMA,
      native_queries: [{ platform: 'splunk', language: 'spl', query: 'index=edr', pipeline: null }],
      benign_patterns: ['backup service'],
      'hunt-target': ['threat-1'],
    } as unknown as BasicStoreEntity);
    await assistHunt(testContext, ADMIN_USER, { hunt_id: 'hunt-1', fields: [HuntAssistField.SigmaRule] });
    const request = sentRequest();
    expect(request.hunt).toMatchObject({ name: 'Saved hunt', hypothesis: 'Saved hypothesis of the hunt', current_sigma_rule: SIGMA.trim() });
    expect(request.hunt.native_queries).toEqual([{ platform: 'splunk', language: 'spl', query: 'index=edr', pipeline: null }]);
    expect(request.benign_patterns).toEqual(['backup service']);
    expect(vi.mocked(publishUserAction).mock.calls[0][0]).toMatchObject({ event_scope: 'update', context_data: { id: 'hunt-1' } });
  });

  it('should not call XTM One when the form says nothing about what to hunt', async () => {
    await expect(assistHunt(testContext, ADMIN_USER, { name: ' ', hypothesis: ' ', prompt: '' })).rejects.toThrow('Say what to hunt');
    expect(vi.mocked(callXtmAgent)).not.toHaveBeenCalled();
  });

  it('should name the cause when XTM One is not configured, cannot be reached or has no model', async () => {
    vi.mocked(isXtmOneConfigured).mockReturnValue(false);
    const notConfigured = await failureOf(assistHunt(testContext, ADMIN_USER, { name: 'APT-X' }));
    expect(notConfigured.extensions.data.failure).toBe('XTM_ONE_NOT_CONFIGURED');
    expect(vi.mocked(callXtmAgent)).not.toHaveBeenCalled();
    vi.mocked(isXtmOneConfigured).mockReturnValue(true);
    // The intent catalog cannot be read: XTM One is down, not missing an agent
    vi.mocked(xtmOneClient.listAgentsForIntent).mockImplementation(async (_context, _intent, onFailure) => {
      onFailure?.({ status: null, code: 'ECONNREFUSED', detail: 'connect ECONNREFUSED 127.0.0.1:8000' });
      return [];
    });
    const unreachable = await failureOf(assistHunt(testContext, ADMIN_USER, { name: 'APT-X' }));
    expect(unreachable.extensions.data.failure).toBe('XTM_ONE_UNREACHABLE');
    expect(unreachable.message).not.toContain('127.0.0.1');
    vi.mocked(xtmOneClient.listAgentsForIntent).mockResolvedValue([]);
    expect((await failureOf(assistHunt(testContext, ADMIN_USER, { name: 'APT-X' }))).extensions.data.failure).toBe('XTM_ONE_NO_AGENT');
    vi.mocked(xtmOneClient.listAgentsForIntent).mockResolvedValue([{ agent_slug: 'opencti-hunt-planner', priority: 0 }] as Awaited<ReturnType<typeof xtmOneClient.listAgentsForIntent>>);
    vi.mocked(callXtmAgent).mockResolvedValue('I\'m sorry, I encountered an error processing your request.');
    expect((await failureOf(assistHunt(testContext, ADMIN_USER, { name: 'APT-X' }))).extensions.data.failure).toBe('XTM_ONE_NO_MODEL');
    vi.mocked(callXtmAgent).mockImplementation(async (_slug, _content, _user, opts) => {
      opts?.onFailure?.({ status: 429, code: 'ERR_BAD_REQUEST', detail: 'Agentic quota exceeded for this period' });
      return null;
    });
    const quota = await failureOf(assistHunt(testContext, ADMIN_USER, { name: 'APT-X' }));
    expect(quota.extensions.data.failure).toBe('XTM_ONE_QUOTA');
    expect(quota.message).toContain('Agentic quota exceeded for this period');
  });

  it('should refuse an answer without the asked field and audit nothing', async () => {
    vi.mocked(callXtmAgent).mockResolvedValue(plannerAnswer({
      hunt_type: 'infrastructure',
      sigma_rule: '',
      native_queries: [{ platform: 'internet', language: 'internet', query: 'services.jarm.fingerprint: abc', pipeline: 'censys' }],
    }));
    const incomplete = await failureOf(assistHunt(testContext, ADMIN_USER, { fields: [HuntAssistField.SigmaRule], hypothesis: 'If APT-X is active', target_ids: ['threat-1'] }));
    expect(incomplete.message).toContain('answered without: sigma_rule');
    expect(incomplete.extensions.data.failure).toBe('XTM_ONE_INCOMPLETE');
    expect(vi.mocked(publishUserAction)).not.toHaveBeenCalled();
  });

  it('should pass on the reasons of an agent that refused its own answer', async () => {
    vi.mocked(callXtmAgent).mockResolvedValue(JSON.stringify({ valid: false, errors: ['hunt_type: a hunt_sigma_generation request asks for a telemetry hunt'] }));
    const refused = await failureOf(assistHunt(testContext, ADMIN_USER, { fields: [HuntAssistField.SigmaRule], hypothesis: 'If APT-X is active' }));
    expect(refused.message).toContain('asks for a telemetry hunt');
    expect(refused.extensions.data.failure).toBe('XTM_ONE_INVALID_ANSWER');
  });
});
