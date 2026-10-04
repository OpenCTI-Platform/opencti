import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  policies: [] as Array<{ internal_id: string; name: string }>,
  runUser: { id: 'user-run-as' } as { id: string } | null,
  addInvestigationRun: vi.fn(),
}));

vi.mock('../../../../src/database/middleware-loader', () => ({ fullEntitiesList: vi.fn(async () => mocks.policies) }));
vi.mock('../../../../src/modules/user/user-domain', () => ({ resolveUserByIdFromCache: vi.fn(async () => mocks.runUser) }));
vi.mock('../../../../src/modules/investigationRun/investigationRun-domain', () => ({ addInvestigationRun: mocks.addInvestigationRun }));
vi.mock('../../../../src/modules/playbook/playbook-utils', () => ({
  isBundleElementInScope: () => true,
  filterBundleElements: async (_: unknown, elements: unknown[]) => elements,
}));
vi.mock('../../../../src/modules/playbook/components/ai-agent-shared', () => ({
  resolveRunAsUserId: (runAs?: { value: string } | null) => runAs?.value ?? null,
}));

const { PLAYBOOK_INVESTIGATION_COMPONENT } = await import('../../../../src/modules/playbook/components/investigation-component');

const octi = (id: string, type: string) => ({ extensions: { 'extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba': { id, type } } });
const bundle = {
  id: 'bundle--1',
  type: 'bundle',
  objects: [
    { id: 'x-opencti-case-incident--1', type: 'x-opencti-case-incident', ...octi('case-1', 'Case-Incident') },
    { id: 'incident--2', type: 'incident', ...octi('incident-2', 'Incident') },
    { id: 'incident--2-again', type: 'incident', ...octi('incident-2', 'Incident') },
    { id: 'indicator--3', type: 'indicator', ...octi('indicator-3', 'Indicator') },
  ],
};
const run = (configuration: Record<string, unknown>, objects = bundle.objects) => PLAYBOOK_INVESTIGATION_COMPONENT.executor({
  dataInstanceId: 'x-opencti-case-incident--1',
  playbookId: 'playbook-1',
  eventId: 'event-1',
  previousPlaybookNodeId: undefined,
  previousStepBundle: null,
  playbookNode: { id: 'node-1', name: 'Run Case Autopilot', component_id: 'PLAYBOOK_INVESTIGATION_COMPONENT', configuration },
  bundle: { ...bundle, objects },
} as never);

describe('Run Case Autopilot playbook component', () => {
  beforeEach(() => {
    mocks.policies = [];
    mocks.runUser = { id: 'user-run-as' };
    mocks.addInvestigationRun.mockReset();
  });

  it('offers the investigation policies by name', async () => {
    mocks.policies = [{ internal_id: 'policy-b', name: 'Ransomware' }, { internal_id: 'policy-a', name: 'Phishing' }];
    const schema = await PLAYBOOK_INVESTIGATION_COMPONENT.schema?.() as unknown as { properties: { policy_id: { oneOf: unknown[] } } };
    expect(schema.properties.policy_id.oneOf).toEqual([{ const: 'policy-a', title: 'Phishing' }, { const: 'policy-b', title: 'Ransomware' }]);
  });

  it('starts one investigation per incident or case of the bundle, as the configured identity, with the policy', async () => {
    mocks.addInvestigationRun.mockRejectedValueOnce(new Error('An investigation of this entity is already running'));
    const result = await run({ applyToElements: 'allElements', policy_id: 'policy-a', run_as: { label: 'Service account', value: 'user-run-as' } });
    expect(result.output_port).toBe('out');
    expect(mocks.addInvestigationRun).toHaveBeenCalledTimes(2);
    expect(mocks.addInvestigationRun.mock.calls.map((call) => call[2])).toEqual(['case-1', 'incident-2']);
    expect(mocks.addInvestigationRun.mock.calls[1][3]).toBe('policy-a');
    expect(mocks.addInvestigationRun.mock.calls[1][4]).toEqual({ trigger: 'playbook', runAsUserId: 'user-run-as' });
  });

  it('starts nothing without an incident or case, or without a run-as identity', async () => {
    await run({ applyToElements: 'allElements' }, [bundle.objects[3]]);
    expect(mocks.addInvestigationRun).not.toHaveBeenCalled();
    mocks.runUser = null;
    const result = await run({ applyToElements: 'allElements' });
    expect(result.output_port).toBe('out');
    expect(mocks.addInvestigationRun).not.toHaveBeenCalled();
  });
});
