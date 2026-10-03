import { describe, expect, it } from 'vitest';
import { NEW_POLICY, toPolicyEditInputs, toPolicyInput, type InvestigationPolicyFormPolicy, type InvestigationPolicyFormValues } from './investigationPolicyUtils';

const stored: InvestigationPolicyFormPolicy = {
  ...NEW_POLICY,
  name: 'SOC policy',
  allowed_actions: ['enrichment', 'create_note'],
  enrichment_connector_ids: ['vt', 'shodan'],
  runAs: { id: 'svc-1', name: 'Autopilot service account' },
};

const formValues = (overrides: Partial<InvestigationPolicyFormValues> = {}): InvestigationPolicyFormValues => ({
  name: 'SOC policy',
  description: '',
  is_default: false,
  pack_id: '',
  agent_slug: '',
  allowed_actions: [{ value: 'create_note', label: 'Note' }, { value: 'enrichment', label: 'Enrichment' }],
  enrichment_connector_ids: [{ value: 'shodan', label: 'Shodan' }, { value: 'vt', label: 'VirusTotal' }],
  approval_connector_ids: [],
  auto_approve_low_risk: false,
  auto_approve_min_confidence: 80,
  attribution_min_confidence: 55,
  max_tool_calls: 40,
  max_enrichment_jobs: 20,
  max_minutes: 60,
  trigger_on_case_rfi_creation: false,
  run_as: { value: 'svc-1', label: 'Autopilot service account' },
  ...overrides,
});

describe('Case Autopilot policy inputs', () => {
  it('builds the creation input from the form', () => {
    const input = toPolicyInput(formValues({ pack_id: ' opencti-case-investigation ', max_minutes: '90' as unknown as number }));
    expect(input.pack_id).toBe('opencti-case-investigation');
    expect(input.agent_slug).toBeNull();
    expect(input.description).toBeNull();
    expect(input.max_minutes).toBe(90);
    expect(input.allowed_actions).toEqual(['create_note', 'enrichment']);
    expect(input.run_as_id).toBe('svc-1');
  });

  it('patches nothing when only the order of list values changed', () => {
    expect(toPolicyEditInputs(stored, formValues())).toEqual([]);
  });

  it('patches only the changed fields, lists as lists and single values wrapped', () => {
    const patch = toPolicyEditInputs(stored, formValues({
      max_tool_calls: 80,
      approval_connector_ids: [{ value: 'shodan', label: 'Shodan' }],
      run_as: null,
      pack_id: 'phishing',
    }));
    expect(patch).toEqual(expect.arrayContaining([
      { key: 'max_tool_calls', value: [80] },
      { key: 'approval_connector_ids', value: ['shodan'] },
      { key: 'run_as_id', value: [null] },
      { key: 'pack_id', value: ['phishing'] },
    ]));
    expect(patch).toHaveLength(4);
  });
});
