import { describe, expect, it } from 'vitest';
import {
  buildHuntAssistRequest,
  classifyXtmCallFailure,
  draftNativeQueries,
  extractJsonObject,
  type HuntAssistDraft,
  huntAgentRefusalErrors,
  huntAssistHasSubject,
  pickHuntAssistance,
  resolveHuntAssistTarget,
  validateHuntAssistDraft,
  validateHuntPlanSpec,
  validateHuntTriageResult,
} from '../../../../src/modules/hunt/hunt-agents';

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

  it('should neither check nor keep the Sigma rule of an infrastructure plan, which runs none', () => {
    const spec = validateHuntPlanSpec(planAnswer({
      hunt_type: 'infrastructure',
      sigma_rule: 'title: broken',
      native_queries: [{ platform: 'internet', language: 'internet', query: 'services.jarm.fingerprint: abc', pipeline: 'censys' }],
    }), []);
    expect(spec.sigma_rule).toBe('');
  });
});

const emptyDraft = (overrides: Partial<HuntAssistDraft> = {}): HuntAssistDraft => ({
  name: '',
  hunt_type: 'telemetry',
  hypothesis: '',
  description: '',
  sigma_rule: '',
  native_queries: [],
  expected_observables: [],
  benign_patterns: [],
  prompt: '',
  ...overrides,
});

const failureOf = (run: () => unknown) => {
  try {
    run();
  } catch (error) {
    return (error as { extensions: { data: { failure?: string } } }).extensions.data.failure;
  }
  return undefined;
};

describe('Hunt assistance requests', () => {
  const plannerRequest = { task: 'hunt_hypothesis', threats: [], benign_patterns: ['backup'], security_platforms: [{ id: 'p-1', platform: 'splunk', languages: ['spl'] }] };

  it('should ask for the Sigma rule alone as a Sigma generation, refining the rule being edited', () => {
    const request = buildHuntAssistRequest(plannerRequest, emptyDraft({ name: 'APT-X', hypothesis: 'If APT-X is active', sigma_rule: SIGMA }), resolveHuntAssistTarget(['sigma_rule'], {}));
    expect(request.task).toBe('hunt_sigma_generation');
    expect(request.hunt_type).toBe('telemetry');
    expect(request.hunt).toMatchObject({ name: 'APT-X', hypothesis: 'If APT-X is active', current_sigma_rule: SIGMA, requested_fields: ['sigma_rule'], analyst_request: null });
    expect(request.security_platforms).toEqual(plannerRequest.security_platforms);
  });

  it('should plan from nothing but the words of the analyst', () => {
    const draft = emptyDraft({ prompt: 'Office documents launching encoded PowerShell' });
    expect(huntAssistHasSubject(draft, 0)).toBe(true);
    const request = buildHuntAssistRequest(plannerRequest, draft, resolveHuntAssistTarget([], {}));
    expect(request.task).toBe('hunt_hypothesis');
    expect(request.hunt).toMatchObject({ analyst_request: 'Office documents launching encoded PowerShell', requested_fields: [], current_sigma_rule: null });
    // Nothing to start from: the platform asks the analyst instead of calling the agent
    expect(huntAssistHasSubject(emptyDraft(), 0)).toBe(false);
    expect(huntAssistHasSubject(emptyDraft(), 1)).toBe(true);
    expect(huntAssistHasSubject(emptyDraft({ name: 'APT-X' }), 0)).toBe(true);
  });

  it('should let the planner write the native query of the platform and language asked for', () => {
    const target = resolveHuntAssistTarget(['native_queries', 'native_queries'], { platform: 'microsoft-sentinel', language: 'KQL' });
    expect(target).toEqual({ fields: ['native_queries'], native_query: { platform: 'microsoft-sentinel', language: 'kql' } });
    const request = buildHuntAssistRequest(plannerRequest, emptyDraft({ name: 'APT-X', hunt_type: 'indicators' }), target);
    expect(request.security_platforms).toEqual([
      ...plannerRequest.security_platforms,
      { id: null, name: 'microsoft-sentinel', security_platform_type: null, platform: 'microsoft-sentinel', languages: ['kql'] },
    ]);
    // An indicator hunt is never planned as such: the planner chooses the type of the logic it writes
    expect(request.hunt_type).toBeUndefined();
    const onKnownPlatform = buildHuntAssistRequest(plannerRequest, emptyDraft(), resolveHuntAssistTarget(['native_queries'], { platform: 'splunk', language: 'spl2' }));
    expect(onKnownPlatform.security_platforms).toEqual([{ id: 'p-1', platform: 'splunk', languages: ['spl', 'spl2'] }]);
    expect(() => resolveHuntAssistTarget(['native_queries'], { platform: 'splunk' })).toThrow('choose them first');
    expect(() => resolveHuntAssistTarget(['native_queries'], { platform: 'nowhere', language: 'spl' })).toThrow('choose them first');
    expect(() => resolveHuntAssistTarget(['hypothesis', 'password'], {})).toThrow('Unknown hunt fields: password');
  });

  it('should bound the draft and keep only the complete native queries of the form', () => {
    expect(() => validateHuntAssistDraft(emptyDraft({ prompt: 'x'.repeat(2001) }))).toThrow('limited to 2000 characters');
    expect(() => validateHuntAssistDraft(emptyDraft({ benign_patterns: Array.from({ length: 51 }, (_, index) => `pattern ${index}`) }))).toThrow('limited to 50 items');
    expect(validateHuntAssistDraft(emptyDraft({ expected_observables: [' StixFile', 'StixFile', ''] })).expected_observables).toEqual(['StixFile']);
    expect(draftNativeQueries([
      { platform: 'splunk', language: 'spl', query: 'index=edr' },
      { platform: 'splunk', language: 'spl', query: 'index=other' },
      { platform: 'microsoft-sentinel', language: 'kql', query: ' ' },
      { platform: '', language: '', query: '' },
    ])).toEqual([{ platform: 'splunk', language: 'spl', query: 'index=edr', pipeline: null }]);
  });
});

describe('Hunt assistance answers', () => {
  it('should propose the asked field with what the same answer implies', () => {
    const proposal = pickHuntAssistance(validateHuntPlanSpec(planAnswer(), ['allowed-threat']), resolveHuntAssistTarget(['hypothesis'], {}));
    expect(proposal.fields).toEqual(['hypothesis']);
    expect(proposal.hypothesis).toBe('If APT-X is active, rundll32 executes a DLL from a user writable path');
    expect(proposal.sigma_rule).toBe(SIGMA.trim());
    expect(proposal.sigma_validation?.valid).toBe(true);
    expect(proposal.technique_ids).toEqual(['T1218.011', 'T1218']);
    expect(proposal.benign_patterns).toEqual(['Signed vendor DLL']);
  });

  it('should list every field for a whole plan', () => {
    const proposal = pickHuntAssistance(validateHuntPlanSpec(planAnswer(), []), resolveHuntAssistTarget([], {}));
    expect(proposal.fields).toEqual(['name', 'hypothesis', 'description', 'sigma_rule', 'native_queries', 'expected_observables', 'benign_patterns', 'techniques']);
    expect(proposal.native_queries).toHaveLength(1);
  });

  it('should keep only the native query asked for', () => {
    const spec = validateHuntPlanSpec(planAnswer(), []);
    expect(pickHuntAssistance(spec, resolveHuntAssistTarget(['native_queries'], { platform: 'splunk', language: 'SPL' })).native_queries)
      .toEqual([{ platform: 'splunk', language: 'spl', query: 'index=edr process=rundll32.exe', pipeline: null }]);
    const missing = () => pickHuntAssistance(spec, resolveHuntAssistTarget(['native_queries'], { platform: 'microsoft-sentinel', language: 'kql' }));
    expect(missing).toThrow('answered without: native_queries');
    expect(failureOf(missing)).toBe('XTM_ONE_INCOMPLETE');
  });

  it('should refuse an answer without the asked field', () => {
    const infrastructure = validateHuntPlanSpec(planAnswer({
      hunt_type: 'infrastructure',
      sigma_rule: '',
      native_queries: [{ platform: 'internet', language: 'internet', query: 'services.jarm.fingerprint: abc', pipeline: 'censys' }],
    }), []);
    expect(() => pickHuntAssistance(infrastructure, resolveHuntAssistTarget(['sigma_rule'], {}))).toThrow('answered without: sigma_rule');
    const withoutPatterns = validateHuntPlanSpec(planAnswer({ benign_patterns: [] }), []);
    expect(() => pickHuntAssistance(withoutPatterns, resolveHuntAssistTarget(['benign_patterns', 'hypothesis'], {}))).toThrow('answered without: benign_patterns');
    expect(failureOf(() => validateHuntPlanSpec(planAnswer({ sigma_rule: 'title: broken' }), []))).toBe('XTM_ONE_INVALID_ANSWER');
  });
});

describe('Hunt agent failures', () => {
  it('should name the cause of a failed XTM One call', () => {
    expect(classifyXtmCallFailure({ status: 429, code: 'ERR_BAD_REQUEST', detail: 'Agentic quota exceeded' })).toBe('XTM_ONE_QUOTA');
    expect(classifyXtmCallFailure({ status: 401, code: null, detail: 'Invalid token' })).toBe('XTM_ONE_REFUSED');
    expect(classifyXtmCallFailure({ status: 403, code: null, detail: null })).toBe('XTM_ONE_REFUSED');
    expect(classifyXtmCallFailure({ status: 500, code: null, detail: 'No LLM provider configured. An admin must add an API key in Settings > AI Models.' })).toBe('XTM_ONE_NO_MODEL');
    expect(classifyXtmCallFailure({ status: null, code: 'ECONNABORTED', detail: 'timeout of 300000ms exceeded' })).toBe('XTM_ONE_TIMEOUT');
    expect(classifyXtmCallFailure({ status: null, code: 'ECONNREFUSED', detail: 'connect ECONNREFUSED 127.0.0.1:8000' })).toBe('XTM_ONE_UNREACHABLE');
    expect(classifyXtmCallFailure({ status: 502, code: null, detail: 'Bad gateway' })).toBe('XTM_ONE_UNREACHABLE');
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
