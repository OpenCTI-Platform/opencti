import { describe, expect, it } from 'vitest';
import { buildHuntSigmaRequest, extractJsonObject, huntAgentRefusalErrors, validateHuntPlanSpec, validateHuntSigmaGeneration, validateHuntTriageResult } from '../../../../src/modules/hunt/hunt-agents';

const SIGMA = 'title: Suspicious rundll32\nlogsource:\n  product: windows\n  category: process_creation\ndetection:\n  selection:\n    Image|endswith: rundll32.exe\n  condition: selection\n';

const planAnswer = (overrides: Record<string, unknown> = {}) => ({
  name: 'APT-X rundll32 proxy execution',
  description: 'Hunt the rundll32 proxy execution of APT-X',
  hypothesis: 'If APT-X is active, rundll32 executes a DLL from a user writable path',
  hunt_type: 'telemetry',
  sigma_rule: SIGMA,
  native_queries: [{ platform: 'splunk', language: 'spl', query: 'index=edr process=rundll32.exe', pipeline: null }],
  expected_observables: ['StixFile', ' StixFile ', 'IPv4-Addr', ''],
  benign_patterns: ['Signed vendor DLL'],
  escalation_threshold: 5,
  time_window_hours: 48,
  technique_ids: ['t1218.011', 'T1218', 'not-an-id'],
  target_ids: ['allowed-threat', 'invented-threat'],
  rationale: 'The report describes rundll32 abuse',
  ...overrides,
});

describe('Hunt planner answers', () => {
  it('should extract the outermost JSON object of an answer', () => {
    expect(extractJsonObject('```json\n{"a": {"b": 1}}\n```')).toEqual({ a: { b: 1 } });
    expect(extractJsonObject('no json')).toBeNull();
    expect(extractJsonObject('{broken')).toBeNull();
    expect(extractJsonObject(null)).toBeNull();
  });

  it('should read the reasons of an agent that refused its own answer', () => {
    expect(huntAgentRefusalErrors({ valid: false, errors: ['target_ids: at most 50 ids', ' ', 3, 'x'.repeat(400)] }))
      .toEqual(['target_ids: at most 50 ids', 'x'.repeat(300)]);
    expect(huntAgentRefusalErrors({ valid: false, errors: Array.from({ length: 30 }, (_, index) => `error ${index}`) })).toHaveLength(10);
    expect(huntAgentRefusalErrors({ valid: false, errors: [] })).toEqual([]);
    // An answer is not a refusal
    expect(huntAgentRefusalErrors(planAnswer())).toBeNull();
    expect(huntAgentRefusalErrors({ valid: true, errors: [] })).toBeNull();
    expect(huntAgentRefusalErrors({ valid: false })).toBeNull();
    expect(huntAgentRefusalErrors([{ valid: false, errors: [] }])).toBeNull();
    expect(huntAgentRefusalErrors(null)).toBeNull();
  });

  it('should normalize a valid plan and ground the targets on the input', () => {
    const spec = validateHuntPlanSpec(planAnswer(), ['allowed-threat']);
    expect(spec.name).toBe('APT-X rundll32 proxy execution');
    expect(spec.expected_observables).toEqual(['StixFile', 'IPv4-Addr']);
    expect(spec.technique_ids).toEqual(['T1218.011', 'T1218']);
    expect(spec.target_ids).toEqual(['allowed-threat']);
    expect(spec.escalation_threshold).toBe(5);
    expect(spec.time_window_hours).toBe(48);
    expect(spec.native_queries).toEqual([{ platform: 'splunk', language: 'spl', query: 'index=edr process=rundll32.exe', pipeline: null }]);
  });

  it('should bound numbers', () => {
    const spec = validateHuntPlanSpec(planAnswer({ escalation_threshold: 0, time_window_hours: 100000 }), []);
    expect(spec.escalation_threshold).toBe(1);
    expect(spec.time_window_hours).toBeLessThanOrEqual(720);
  });

  it('should refuse answers outside the contract', () => {
    expect(() => validateHuntPlanSpec({ name: 'x' }, [])).toThrow('does not match the hunt spec schema');
    expect(() => validateHuntPlanSpec(planAnswer({ hunt_type: 'other' }), [])).toThrow('does not match the hunt spec schema');
    // An indicator hunt is built from the indicators themselves, the planner never proposes one
    expect(() => validateHuntPlanSpec(planAnswer({ hunt_type: 'indicators' }), [])).toThrow('does not match the hunt spec schema');
    expect(() => validateHuntPlanSpec(planAnswer({ sigma_rule: '', native_queries: [] }), [])).toThrow('Add a Sigma rule or a native query');
    // A plan the activation would refuse is refused at planning: an internet query does not run a telemetry hunt
    expect(() => validateHuntPlanSpec(planAnswer({ sigma_rule: '', native_queries: [{ platform: 'internet', language: 'internet', query: 'services.port: 443', pipeline: 'censys' }] }), []))
      .toThrow('Add a Sigma rule or a native query');
    expect(() => validateHuntPlanSpec(planAnswer({ sigma_rule: 'title: broken' }), [])).toThrow('invalid Sigma rule');
    expect(() => validateHuntPlanSpec(planAnswer({ hunt_type: 'infrastructure', sigma_rule: '' }), [])).toThrow('Add a native query for the internet platform');
    expect(() => validateHuntPlanSpec(planAnswer({ native_queries: [{ platform: 'nowhere', language: 'x', query: 'y' }] }), [])).toThrow('platform must be one of');
  });

  it('should accept an infrastructure plan with an internet query', () => {
    const spec = validateHuntPlanSpec(planAnswer({
      hunt_type: 'infrastructure',
      sigma_rule: '',
      native_queries: [{ platform: 'internet', language: 'internet', query: 'services.jarm.fingerprint: abc', pipeline: 'censys' }],
    }), []);
    expect(spec.hunt_type).toBe('infrastructure');
    expect(spec.sigma_rule).toBe('');
  });
});

describe('Hunt Sigma rule generation', () => {
  it('should ask for the Sigma rule of the hunt being written, refining its current rule', () => {
    const request = buildHuntSigmaRequest({ task: 'hunt_hypothesis', threats: [], benign_patterns: ['backup'] }, { name: 'APT-X', hypothesis: 'If APT-X is active', sigma_rule: SIGMA });
    expect(request).toEqual({
      task: 'hunt_sigma_generation',
      threats: [],
      benign_patterns: ['backup'],
      hunt_type: 'telemetry',
      hunt: { name: 'APT-X', hypothesis: 'If APT-X is active', current_sigma_rule: SIGMA },
    });
    expect(buildHuntSigmaRequest({}, { name: '', hypothesis: 'h', sigma_rule: '' }).hunt.current_sigma_rule).toBeNull();
  });

  it('should keep the checked Sigma rule of the answer with what the platform reads from it', () => {
    const generation = validateHuntSigmaGeneration(planAnswer(), ['allowed-threat']);
    expect(generation.sigma_rule).toBe(SIGMA.trim());
    expect(generation.validation.valid).toBe(true);
    expect(generation.validation.logsource_product).toBe('windows');
    expect(generation.technique_ids).toEqual(['T1218.011', 'T1218']);
    expect(generation.rationale).toBe('The report describes rundll32 abuse');
  });

  it('should refuse an answer without a Sigma rule or with an invalid one', () => {
    expect(() => validateHuntSigmaGeneration(planAnswer({
      hunt_type: 'infrastructure',
      sigma_rule: '',
      native_queries: [{ platform: 'internet', language: 'internet', query: 'services.jarm.fingerprint: abc', pipeline: 'censys' }],
    }), [])).toThrow('contains no Sigma rule');
    expect(() => validateHuntSigmaGeneration(planAnswer({ sigma_rule: '' }), [])).toThrow('contains no Sigma rule');
    expect(() => validateHuntSigmaGeneration(planAnswer({ sigma_rule: 'title: broken' }), [])).toThrow('invalid Sigma rule');
  });
});

describe('Hunt triage answers', () => {
  it('should keep the incident of a true positive only', () => {
    const incident = { name: 'APT-X on host', description: 'Confirmed', severity: 'high' };
    expect(validateHuntTriageResult({ verdict: 'true_positive', confidence: 90, rationale: ' clear ', incident }))
      .toEqual({ verdict: 'true_positive', confidence: 90, rationale: 'clear', incident });
    expect(validateHuntTriageResult({ verdict: 'benign', confidence: 70, rationale: 'admin tool', incident }).incident).toBeNull();
  });

  it('should refuse verdicts and confidences outside the contract', () => {
    expect(() => validateHuntTriageResult({ verdict: 'pending', confidence: 50, rationale: 'r' })).toThrow('triage schema');
    expect(() => validateHuntTriageResult({ verdict: 'benign', confidence: 150, rationale: 'r' })).toThrow('triage schema');
    expect(() => validateHuntTriageResult({ verdict: 'benign', confidence: 50, rationale: '' })).toThrow('triage schema');
    expect(() => validateHuntTriageResult({ verdict: 'true_positive', confidence: 50, rationale: 'r', incident: { name: 'n', description: 'd', severity: 'huge' } })).toThrow('triage schema');
  });

  it('should keep a confidence the triage could not assess as null, never as a number', () => {
    expect(validateHuntTriageResult({ verdict: 'inconclusive', confidence: null, rationale: 'sample too small' }))
      .toEqual({ verdict: 'inconclusive', confidence: null, rationale: 'sample too small', incident: null });
    // The key stays mandatory: an answer that omits it is refused rather than defaulted
    expect(() => validateHuntTriageResult({ verdict: 'inconclusive', rationale: 'r' })).toThrow('triage schema');
  });
});
