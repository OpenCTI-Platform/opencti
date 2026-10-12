import { describe, expect, it } from 'vitest';
import {
  DEFAULT_PACK_VALUE,
  NEW_POLICY,
  toPackOptions,
  toPolicyEditInputs,
  toPolicyInput,
  type InvestigationPolicyFormPolicy,
  type InvestigationPolicyFormValues,
} from './investigationPolicyUtils';

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
  pack_id: DEFAULT_PACK_VALUE,
  pack_options: {},
  agent_slug: '',
  allowed_actions: [{ value: 'create_note', label: 'Note' }, { value: 'enrichment', label: 'Enrichment' }],
  enrichment_connector_ids: [{ value: 'shodan', label: 'Shodan' }, { value: 'vt', label: 'VirusTotal' }],
  approval_connector_ids: [],
  auto_approve_low_risk: false,
  auto_approve_min_confidence: 80,
  attribution_min_confidence: 55,
  max_iterations: 10,
  max_enrichment_jobs: 20,
  max_minutes: 60,
  trigger_on_case_rfi_creation: false,
  run_as: { value: 'svc-1', label: 'Autopilot service account' },
  ...overrides,
});

describe('Case Autopilot policy inputs', () => {
  it('builds the creation input from the form', () => {
    const input = toPolicyInput(formValues({
      pack_id: ' opencti-case-investigation ',
      pack_options: { depth: 'deep' },
      max_minutes: '90' as unknown as number,
    }));
    expect(input.pack_id).toBe('opencti-case-investigation');
    expect(input.pack_options).toEqual({ depth: 'deep' });
    expect(input.agent_slug).toBeNull();
    expect(input.description).toBeNull();
    expect(input.max_minutes).toBe(90);
    expect(input.max_iterations).toBe(10);
    expect(input.allowed_actions).toEqual(['create_note', 'enrichment']);
    expect(input.run_as_id).toBe('svc-1');
  });

  it('names no pack and stores no option for the default pack', () => {
    const input = toPolicyInput(formValues({ pack_options: { depth: 'deep' } }));
    expect(input.pack_id).toBeNull();
    expect(input.pack_options).toBeNull();
  });

  it('keeps only the string choices of stored pack options', () => {
    expect(toPackOptions({ depth: 'deep', sources: 3, empty: '', nested: { a: 'b' } })).toEqual({ depth: 'deep' });
    expect(toPackOptions(null)).toEqual({});
    expect(toPackOptions(['deep'])).toEqual({});
  });

  it('patches nothing when only the order of list values changed', () => {
    expect(toPolicyEditInputs(stored, formValues())).toEqual([]);
  });

  it('patches nothing when the pack options are the same in another key order', () => {
    const withOptions = { ...stored, pack_id: 'phishing', pack_options: { depth: 'deep', scope: 'tenant' } };
    expect(toPolicyEditInputs(withOptions, formValues({ pack_id: 'phishing', pack_options: { scope: 'tenant', depth: 'deep' } }))).toEqual([]);
  });

  it('patches only the changed fields, lists as lists and single values wrapped', () => {
    const patch = toPolicyEditInputs(stored, formValues({
      max_iterations: 20,
      approval_connector_ids: [{ value: 'shodan', label: 'Shodan' }],
      run_as: null,
      pack_id: 'phishing',
      pack_options: { depth: 'deep' },
    }));
    expect(patch).toEqual(expect.arrayContaining([
      { key: 'max_iterations', value: [20] },
      { key: 'approval_connector_ids', value: ['shodan'] },
      { key: 'run_as_id', value: [null] },
      { key: 'pack_id', value: ['phishing'] },
      { key: 'pack_options', value: [{ depth: 'deep' }] },
    ]));
    expect(patch).toHaveLength(5);
  });
});
