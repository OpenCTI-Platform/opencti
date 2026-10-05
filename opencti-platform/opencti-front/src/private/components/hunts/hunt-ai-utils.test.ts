import { describe, expect, it } from 'vitest';
import {
  huntAIAcceptedChanges,
  huntAIFailureOf,
  type HuntAIFormValues,
  huntAIHasSubject,
  huntAIPartReplaces,
  type HuntAIProposal,
  huntAIProposalParts,
  huntAssistInput,
} from './hunt-ai-utils';

const proposal = (overrides: Partial<HuntAIProposal> = {}): HuntAIProposal => ({
  fields: ['hypothesis'],
  name: 'APT-X encoded PowerShell',
  hypothesis: 'If APT-X is active, PowerShell runs an encoded command',
  description: 'Hunts the encoded PowerShell of APT-X',
  sigma_rule: 'title: Encoded PowerShell',
  native_queries: [{ platform: 'splunk', language: 'spl', query: 'index=edr CommandLine="* -enc *"', pipeline: null }],
  expected_observables: ['Process'],
  benign_patterns: ['Configuration management agents'],
  techniques: [{ id: 'technique-1', entity_type: 'Attack-Pattern', name: 'PowerShell', x_mitre_id: 'T1059.001' }],
  unknown_technique_ids: [],
  rationale: 'APT-X runs encoded PowerShell',
  ...overrides,
});

const form = (overrides: Partial<HuntAIFormValues> = {}): HuntAIFormValues => ({
  name: '',
  hunt_type: 'telemetry',
  hypothesis: '',
  description: '',
  sigma_rule: '',
  native_queries: [],
  expected_observables: [],
  benign_patterns: '',
  huntTargets: [],
  huntTechniques: [],
  huntSources: [],
  scopePlatforms: [],
  iocElements: [],
  iocEntities: [],
  ...overrides,
});

describe('AI assistance of the hunt forms', () => {
  it('should know when the form says nothing about what to hunt', () => {
    expect(huntAIHasSubject(form())).toBe(false);
    expect(huntAIHasSubject(form({ name: 'APT-X' }))).toBe(true);
    expect(huntAIHasSubject(form({ huntTechniques: [{ value: 't', label: 'T1059' }] }))).toBe(true);
    expect(huntAIHasSubject(form({ native_queries: [{ platform: 'splunk', language: 'spl', query: 'index=edr', pipeline: '' }] }))).toBe(true);
    // A saved hunt always has something to start from
    expect(huntAIHasSubject({ sigma_rule: '' }, 'hunt-1')).toBe(true);
  });

  it('should send every field the form holds, and only those', () => {
    const input = huntAssistInput(form({
      name: 'APT-X',
      benign_patterns: 'backup\n\nscanner',
      huntTargets: [{ value: 'threat-1', label: 'APT-X' }],
      huntSources: [{ value: 'report-1', label: 'Report' }],
      iocEntities: [{ value: 'indicator-1', label: 'Indicator' }],
      native_queries: [{ platform: 'splunk', language: 'spl', query: 'index=edr', pipeline: '' }, { platform: 'elastic-security', language: '', query: '', pipeline: '' }],
    }), { kind: 'hypothesis' }, { prompt: '  ' });
    expect(input).toMatchObject({
      fields: ['hypothesis'],
      name: 'APT-X',
      hunt_type: 'telemetry',
      benign_patterns: ['backup', 'scanner'],
      target_ids: ['threat-1'],
      source_ids: ['report-1', 'indicator-1'],
      native_queries: [{ platform: 'splunk', language: 'spl', query: 'index=edr', pipeline: null }],
    });
    expect(input).not.toHaveProperty('prompt');
    // The Logic tab holds its logic only: the saved hunt completes the rest
    const logic = huntAssistInput({ sigma_rule: 'title: x', native_queries: [{ platform: 'splunk', language: 'spl', query: '', pipeline: '' }] }, { kind: 'native_queries', nativeQueryIndex: 0 }, { huntId: 'hunt-1', prompt: 'lateral movement' });
    expect(logic).toEqual({
      fields: ['native_queries'],
      prompt: 'lateral movement',
      native_query_platform: 'splunk',
      native_query_language: 'spl',
      hunt_id: 'hunt-1',
      sigma_rule: 'title: x',
      native_queries: [],
    });
    expect(huntAssistInput(form(), { kind: 'plan' }, {}).fields).toEqual([]);
  });

  it('should read the cause of a failure from the payload or the network error', () => {
    expect(huntAIFailureOf([{ message: 'The AI quota of XTM One is used up: 0 left', extensions: { data: { failure: 'XTM_ONE_QUOTA' } } }], 'fallback'))
      .toEqual({ failure: 'XTM_ONE_QUOTA', message: 'The AI quota of XTM One is used up: 0 left' });
    expect(huntAIFailureOf([{ message: 'Boom', data: { failure: 'SOMETHING_ELSE' } }], 'fallback')).toEqual({ failure: 'UNKNOWN', message: 'Boom' });
    expect(huntAIFailureOf(undefined, 'fallback')).toEqual({ failure: 'UNKNOWN', message: 'fallback' });
  });

  it('should propose the asked field first and offer what the answer implies for the empty fields', () => {
    const parts = huntAIProposalParts(proposal(), form({ name: 'APT-X', description: 'Written by the analyst' }), { kind: 'hypothesis' });
    expect(parts.primary).toEqual(['hypothesis']);
    // The description the analyst wrote is never offered; the name is not empty either
    expect(parts.secondary).toEqual(['sigma_rule', 'expected_observables', 'benign_patterns', 'technique:technique-1']);
    // An indicator hunt shows neither a Sigma rule nor observables to extract
    expect(huntAIProposalParts(proposal(), form({ hunt_type: 'indicators' }), { kind: 'hypothesis' }).secondary)
      .toEqual(['name', 'description', 'benign_patterns', 'technique:technique-1']);
    // A technique already in the form is not offered again
    expect(huntAIProposalParts(proposal(), form({ huntTechniques: [{ value: 'technique-1', label: 'PowerShell' }] }), { kind: 'sigma_rule' }).secondary).not.toContain('technique:technique-1');
  });

  it('should plan every field the form holds, without renaming a named hunt', () => {
    expect(huntAIProposalParts(proposal(), form({ name: 'APT-X' }), { kind: 'plan' }).primary)
      .toEqual(['hypothesis', 'description', 'sigma_rule', 'native_queries', 'expected_observables', 'benign_patterns', 'technique:technique-1']);
    expect(huntAIProposalParts(proposal(), form(), { kind: 'plan' }).primary[0]).toBe('name');
    expect(huntAIPartReplaces(form({ description: 'Mine' }), 'description', { kind: 'plan' })).toBe(true);
    expect(huntAIPartReplaces(form(), 'description', { kind: 'plan' })).toBe(false);
  });

  it('should write the asked field as edited, and merge what the analyst also adds', () => {
    const values = form({
      expected_observables: ['StixFile'],
      benign_patterns: 'backup',
      huntTechniques: [{ value: 'technique-0', label: 'T1003' }],
    });
    const changes = huntAIAcceptedChanges(proposal({ expected_observables: ['Process', 'StixFile'] }), values, { kind: 'hypothesis' }, ['hypothesis', 'expected_observables', 'benign_patterns', 'technique:technique-1'], { hypothesis: 'Edited hypothesis' });
    expect(changes).toEqual([
      ['hypothesis', 'Edited hypothesis'],
      ['expected_observables', ['StixFile', 'Process']],
      ['benign_patterns', 'backup\nConfiguration management agents'],
      ['huntTechniques', [{ value: 'technique-0', label: 'T1003' }, { value: 'technique-1', label: '[T1059.001] PowerShell', type: 'Attack-Pattern' }]],
    ]);
    // Asked for, the observables are replaced by the proposal as the analyst left it
    expect(huntAIAcceptedChanges(proposal(), values, { kind: 'expected_observables' }, ['expected_observables'], { expected_observables: [] })).toEqual([['expected_observables', []]]);
  });

  it('should write a native query into its row, and a planned one by platform', () => {
    const values = form({ native_queries: [{ platform: 'splunk', language: 'spl', query: '', pipeline: '' }] });
    expect(huntAIAcceptedChanges(proposal(), values, { kind: 'native_queries', nativeQueryIndex: 0 }, ['native_queries'])).toEqual([
      ['native_queries.0.query', 'index=edr CommandLine="* -enc *"'],
    ]);
    const planned = huntAIAcceptedChanges(
      proposal({ native_queries: [{ platform: 'splunk', language: 'spl', query: 'index=new', pipeline: null }, { platform: 'elastic-security', language: 'esql', query: 'FROM logs', pipeline: null }] }),
      values,
      { kind: 'plan' },
      ['native_queries'],
    );
    expect(planned).toEqual([['native_queries', [
      { platform: 'splunk', language: 'spl', query: 'index=new', pipeline: '' },
      { platform: 'elastic-security', language: 'esql', query: 'FROM logs', pipeline: '' },
    ]]]);
  });
});
