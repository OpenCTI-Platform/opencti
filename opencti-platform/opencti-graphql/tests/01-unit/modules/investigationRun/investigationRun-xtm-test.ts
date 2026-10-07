import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest';
import nconf from 'nconf';

const http = vi.hoisted(() => ({ post: vi.fn(), get: vi.fn(), options: [] as unknown[] }));
const catalog = vi.hoisted(() => ({ configured: true, agents: [] as Array<{ agent_slug?: string }> }));

vi.mock('../../../../src/utils/http-client', () => ({
  getHttpClient: (options: unknown) => {
    http.options.push(options);
    return { post: http.post, get: http.get };
  },
  getResponseError: (error: { response?: { status: number; data: unknown } }) => error?.response ?? null,
}));
vi.mock('../../../../src/domain/xtm-auth', () => ({ issueXtmJwt: vi.fn(async () => 'platform-jwt') }));
vi.mock('../../../../src/modules/xtm/one/xtm-one-client', () => ({
  default: {
    isConfigured: () => catalog.configured,
    listAgentsForIntent: vi.fn(async () => catalog.agents),
  },
}));

const {
  cancelInvestigation,
  getInvestigation,
  listInvestigationPacks,
  pushInvestigationFeedback,
  resolveInvestigationAgent,
  startInvestigation,
} = await import('../../../../src/modules/investigationRun/investigationRun-xtm');

const jwtUser = { id: 'user-1', user_email: 'analyst@example.com' };
const httpError = (status: number, data: unknown = { detail: `status ${status}` }) => Object.assign(new Error(`Request failed with status ${status}`), { response: { status, data } });
const previousUrl = nconf.get('xtm:xtm_one_url');

describe('Case Autopilot client of the XTM One investigation engine', () => {
  beforeEach(() => {
    nconf.set('xtm:xtm_one_url', 'https://xtm-one.example.com');
    catalog.configured = true;
    catalog.agents = [];
    http.post.mockReset();
    http.get.mockReset();
    http.options.length = 0;
  });
  afterAll(() => {
    nconf.set('xtm:xtm_one_url', previousUrl);
  });

  it('resolves the agent of the investigation intent, honouring a pinned agent only while it is bound', async () => {
    catalog.agents = [{ agent_slug: 'custom-investigator' }, { agent_slug: 'deep-investigation-agent' }, {}];
    expect(await resolveInvestigationAgent(jwtUser)).toBe('deep-investigation-agent');
    expect(await resolveInvestigationAgent(jwtUser, 'custom-investigator')).toBe('custom-investigator');
    expect(await resolveInvestigationAgent(jwtUser, 'retired-agent')).toBeNull();
    catalog.agents = [{ agent_slug: 'custom-investigator' }];
    expect(await resolveInvestigationAgent(jwtUser)).toBe('custom-investigator');
    catalog.agents = [];
    expect(await resolveInvestigationAgent(jwtUser)).toBeNull();
  });

  it('starts an engine run scoped to the run draft', async () => {
    http.post.mockResolvedValueOnce({ data: { id: 'inv-1', status: 'planning', revision: 0 } });
    const result = await startInvestigation(jwtUser, { schema: 'opencti.investigation.start/v1' }, 'draft-1');
    expect(result).toMatchObject({ ok: true, value: { id: 'inv-1', status: 'planning' } });
    expect(http.post).toHaveBeenCalledWith('/api/v1/platform/investigations', { schema: 'opencti.investigation.start/v1' }, expect.anything());
    expect(http.options[0]).toMatchObject({
      baseURL: 'https://xtm-one.example.com',
      headers: { Authorization: 'Bearer platform-jwt', 'X-Platform-Product': 'opencti', 'opencti-draft-id': 'draft-1' },
    });
  });

  it('reads and cancels an engine run', async () => {
    http.get.mockResolvedValueOnce({ data: { investigation_id: 'inv-2', status: 'running', revision: 3 } });
    expect(await getInvestigation(jwtUser, 'inv/2', null)).toMatchObject({ ok: true, value: { id: 'inv-2', revision: 3 } });
    expect(http.get).toHaveBeenCalledWith('/api/v1/platform/investigations/inv%2F2', expect.anything());
    expect(http.options[0]).not.toMatchObject({ headers: { 'opencti-draft-id': expect.anything() } });
    http.post.mockResolvedValueOnce({ data: {} });
    expect(await cancelInvestigation(jwtUser, 'inv-2')).toEqual({ ok: true, value: true });
  });

  it('names why the engine cannot answer, and never falls back', async () => {
    catalog.configured = false;
    expect(await startInvestigation(jwtUser, {}, null)).toMatchObject({ ok: false, failure: 'engine_not_configured' });
    catalog.configured = true;
    http.get.mockRejectedValueOnce(httpError(403));
    expect(await getInvestigation(jwtUser, 'inv-3', null)).toMatchObject({ ok: false, failure: 'engine_disabled', status: 403, message: 'status 403' });
    http.get.mockRejectedValueOnce(httpError(404, { message: 'Not Found' }));
    expect(await getInvestigation(jwtUser, 'inv-3', null)).toMatchObject({ ok: false, failure: 'engine_unavailable', status: 404, message: 'Not Found' });
    http.get.mockRejectedValueOnce(new Error('connect ECONNREFUSED'));
    expect(await getInvestigation(jwtUser, 'inv-3', null)).toMatchObject({ ok: false, failure: 'engine_unreachable', status: null, message: 'connect ECONNREFUSED' });
    http.get.mockResolvedValueOnce({ data: { unexpected: true } });
    expect(await getInvestigation(jwtUser, 'inv-3', null)).toMatchObject({ ok: false, failure: 'engine_unreachable' });
  });

  it('lists the packs of the engine', async () => {
    http.get.mockResolvedValueOnce({
      data: {
        packs: [
          { slug: 'opencti-case-investigation', label: 'OpenCTI case investigation', recommended: true, applicable_source_count: 4, total_source_count: '6', options: [{ key: 'leads', choices: [{ value: 'on' }, {}] }, {}] },
          { label: 'No slug' },
        ],
      },
    });
    const result = await listInvestigationPacks(jwtUser);
    expect(result).toMatchObject({ ok: true, value: [{ slug: 'opencti-case-investigation', recommended: true, total_source_count: 6, max_iterations: null, options: [{ key: 'leads', label: 'leads', choices: [{ value: 'on', label: 'on' }] }] }] });
    http.get.mockResolvedValueOnce({ data: 'not a catalog' });
    expect(await listInvestigationPacks(jwtUser)).toMatchObject({ ok: false, failure: 'engine_unreachable' });
  });

  it('pushes analyst decisions as best effort', async () => {
    const payload = { agent_slug: 'deep-investigation-agent', run_id: 'run-1', subject: { id: 'case-1', entity_type: 'Case-Incident', name: 'Case' }, decisions: [{ decision: 'accepted' }] };
    expect(await pushInvestigationFeedback(jwtUser, { ...payload, decisions: [] })).toBe(false);
    http.post.mockResolvedValueOnce({ data: {} });
    expect(await pushInvestigationFeedback(jwtUser, payload)).toBe(true);
    expect(http.post).toHaveBeenCalledWith('/api/v1/platform/investigations/feedback', payload, expect.anything());
    http.post.mockRejectedValueOnce(httpError(404));
    expect(await pushInvestigationFeedback(jwtUser, payload)).toBe(false);
    catalog.configured = false;
    expect(await pushInvestigationFeedback(jwtUser, payload)).toBe(false);
  });
});
