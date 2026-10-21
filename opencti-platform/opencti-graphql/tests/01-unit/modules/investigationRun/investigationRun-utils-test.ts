import { describe, expect, it } from 'vitest';
import {
  intersectOrganizationIds,
  isCreationSharingWidened,
  isMemberRestricted,
  isTransientFailure,
  runCitedIds,
  runReceivedIds,
  runSourceIds,
  withheldRunContent,
  withoutMemberRestricted,
} from '../../../../src/modules/investigationRun/investigationRun-utils';
import {
  InvestigationApprovalKind,
  InvestigationApprovalStatus,
  InvestigationEnrichmentRequestStatus,
  InvestigationEnrichmentWaveStatus,
  InvestigationStepStatus,
} from '../../../../src/generated/graphql';
import { buildRun } from './investigationRun-fixtures';
import { RELATION_GRANTED_TO } from '../../../../src/schema/stixRefRelationship';
import { ENTITY_TYPE_INTRUSION_SET, ENTITY_TYPE_MALWARE } from '../../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../../../../src/schema/stixMetaObject';
import { KNOWLEDGE_ORGANIZATION_RESTRICT } from '../../../../src/utils/access';
import type { AuthUser } from '../../../../src/types/user';
import type { BasicStoreSettings } from '../../../../src/types/settings';
import { DatabaseError, DraftLockedError, ForbiddenAccess, FunctionalError, LockTimeoutError, TYPE_LOCK_ERROR } from '../../../../src/config/errors';

const sharedWith = (entityType: string, organizations: string[]) => ({ entity_type: entityType, [RELATION_GRANTED_TO]: organizations });
const userOf = (organizations: string[], capabilities: string[] = []) => ({
  id: 'user',
  organizations: organizations.map((id) => ({ internal_id: id })),
  capabilities: capabilities.map((name) => ({ name })),
  user_service_account: false,
} as unknown as AuthUser);
const withPlatformOrganization = { platform_organization: 'platform-org' } as unknown as BasicStoreSettings;
const withoutPlatformOrganization = {} as unknown as BasicStoreSettings;

describe('Case Autopilot restrictive organization sharing', () => {
  it('narrows the sharing to the organizations every cited object is shared with', () => {
    const cited = [sharedWith(ENTITY_TYPE_MALWARE, ['org-a', 'org-b']), sharedWith(ENTITY_TYPE_INTRUSION_SET, ['org-b', 'org-c'])];
    expect(intersectOrganizationIds(['org-a', 'org-b', 'org-c'], cited)).toEqual(['org-b']);
  });

  it('keeps the platform organization only when the citations share no organization', () => {
    expect(intersectOrganizationIds(['org-a'], [sharedWith(ENTITY_TYPE_MALWARE, ['org-b'])])).toEqual([]);
    expect(intersectOrganizationIds(['org-a'], [sharedWith(ENTITY_TYPE_MALWARE, [])])).toEqual([]);
  });

  it('ignores objects visible whatever the organization', () => {
    expect(intersectOrganizationIds(['org-a'], [sharedWith(ENTITY_TYPE_MARKING_DEFINITION, [])])).toEqual(['org-a']);
  });

  it('detects an identity that would share outputs beyond the organizations of the evidence', () => {
    // Outside the platform organization, without the restriction capability: its own organizations apply.
    expect(isCreationSharingWidened(userOf(['org-a', 'org-b']), withPlatformOrganization, false, ['org-b'])).toBe(true);
    expect(isCreationSharingWidened(userOf(['org-b']), withPlatformOrganization, false, ['org-b', 'org-c'])).toBe(false);
    // The requested organizations apply when the identity may restrict.
    expect(isCreationSharingWidened(userOf(['org-a', 'org-b'], [KNOWLEDGE_ORGANIZATION_RESTRICT]), withPlatformOrganization, false, ['org-b'])).toBe(false);
    // Inside the platform organization, nothing is shared beyond it.
    expect(isCreationSharingWidened(userOf(['org-a']), withPlatformOrganization, true, [])).toBe(false);
    // Without a platform organization there is no organization segregation.
    expect(isCreationSharingWidened(userOf(['org-a']), withoutPlatformOrganization, false, [])).toBe(false);
  });
});

describe('Case Autopilot transient failures', () => {
  it('retries what a later pass may not meet again', () => {
    expect(isTransientFailure(DatabaseError('Search engine unavailable'))).toBe(true);
    expect(isTransientFailure(LockTimeoutError({ participantIds: ['run-1'] }))).toBe(true);
    expect(isTransientFailure(DraftLockedError())).toBe(true);
    expect(isTransientFailure(Object.assign(new Error('aborted'), { name: TYPE_LOCK_ERROR }))).toBe(true);
    expect(isTransientFailure(Object.assign(new Error('socket hang up'), { code: 'ECONNRESET' }))).toBe(true);
    expect(isTransientFailure(Object.assign(new Error('no living connections'), { name: 'NoLivingConnectionsError' }))).toBe(true);
    expect(isTransientFailure(new Error('wrapped', { cause: Object.assign(new Error('refused'), { code: 'ECONNREFUSED' }) }))).toBe(true);
  });

  it('fails at once on what a retry cannot fix', () => {
    expect(isTransientFailure(FunctionalError('The policy of the run no longer allows creating its case'))).toBe(false);
    expect(isTransientFailure(ForbiddenAccess())).toBe(false);
    expect(isTransientFailure(new TypeError('Cannot read properties of undefined'))).toBe(false);
    expect(isTransientFailure(null)).toBe(false);
    expect(isTransientFailure('timeout')).toBe(false);
  });
});

describe('Case Autopilot member restrictions', () => {
  it('never reads or cites an element restricted to authorized members', () => {
    const open = { internal_id: 'open', restricted_members: [] };
    const restricted = { internal_id: 'restricted', restricted_members: [{ id: 'user-1', access_right: 'view' }] };
    expect(isMemberRestricted(open)).toBe(false);
    expect(isMemberRestricted({ internal_id: 'none' })).toBe(false);
    expect(isMemberRestricted(null)).toBe(false);
    expect(isMemberRestricted(restricted)).toBe(true);
    expect(withoutMemberRestricted([open, restricted]).map((element) => element.internal_id)).toEqual(['open']);
  });
  it('reads an element every user may read, such as a PIR with its default members', () => {
    const everyone = { internal_id: 'pir', restricted_members: [{ id: 'user-1', access_right: 'admin' }, { id: 'ALL', access_right: 'view' }] };
    const everyoneInGroups = { internal_id: 'grouped', restricted_members: [{ id: 'ALL', access_right: 'view', groups_restriction_ids: ['group-1'] }] };
    const unknownRight = { internal_id: 'unknown', restricted_members: [{ id: 'ALL', access_right: 'none' }] };
    expect(isMemberRestricted(everyone)).toBe(false);
    expect(isMemberRestricted(everyoneInGroups)).toBe(true);
    expect(isMemberRestricted(unknownRight)).toBe(true);
    expect(withoutMemberRestricted([everyone, everyoneInGroups, unknownRight]).map((element) => element.internal_id)).toEqual(['pir']);
  });
});

describe('Case Autopilot access boundary of a run', () => {
  const coursedRun = () => buildRun({
    case_id: 'case-1',
    case_ids: ['case-1', 'case-incident--1'],
    recommendations: [{ ...buildRun().recommendations[0], id: 'r2', course_of_action_id: 'coa-1' }],
  });

  it('names what a run cites: its evidence objects, its hypothesis candidates and its courses of action', () => {
    expect(runCitedIds(coursedRun())).toEqual(['incident-1', 'ip-1', 'indicator-1', 'apt28', 'coa-1']);
  });

  it('carries the access of its subject, its case and what it cites', () => {
    expect(runSourceIds(coursedRun())).toEqual(['incident-1', 'case-1', 'case-incident--1', 'ip-1', 'indicator-1', 'apt28', 'coa-1']);
  });

  it('carries the access of the context the engine received, cited or not', () => {
    const run = { ...coursedRun(), context_ids: ['report-1', 'relationship-1', 'ip-1'] };
    expect(runSourceIds(run)).toEqual(['incident-1', 'case-1', 'case-incident--1', 'report-1', 'relationship-1', 'ip-1', 'indicator-1', 'apt28', 'coa-1']);
  });

  it('names what the engine received: the context and what the enrichment waves brought, endpoints included', () => {
    const run = buildRun({
      context_ids: ['report-1'],
      enrichment_waves: [{
        id: 'wave-1',
        status: InvestigationEnrichmentWaveStatus.Completed,
        requested_at: '2026-10-04T10:00:00.000Z',
        request_ids: ['request-1'],
        delta_computed: true,
        delta: [
          { id: 'domain-1', standard_id: 'domain-name--1', entity_type: 'Domain-Name', action: 'created' },
          { id: 'rel-1', standard_id: 'relationship--1', entity_type: 'resolves-to', action: 'created', from_id: 'domain-1', to_id: 'ip-9' },
        ],
      }],
    });
    expect(runReceivedIds(run)).toEqual(['report-1', 'domain-1', 'domain-name--1', 'rel-1', 'relationship--1', 'ip-9']);
    expect(runSourceIds(run)).toEqual(expect.arrayContaining(['report-1', 'domain-name--1', 'rel-1', 'ip-9']));
  });

  it('withholds everything a run derived, and the approvals and requests quoting it', () => {
    const run = buildRun({
      goal_plan: { objective: 'Investigate the phishing wave' },
      steps: [{ id: 's1', investigation_id: 'inv-1', position: 0, action: 'context_read', source_name: 'Read the case', status: InvestigationStepStatus.Completed, detail_params: { count: 2 }, findings_count: 2, evidence_count: 1 }],
      enrichment_waves: [{ id: 'w1', status: 'completed', requested_at: '2026-10-01T10:00:00.000Z', request_ids: ['q1'], delta: [{ id: 'ip-2', entity_type: 'IPv4-Addr' }], delta_computed: true }],
      approvals: [
        { id: 'a1', kind: InvestigationApprovalKind.Recommendation, status: InvestigationApprovalStatus.Pending, description: 'Block 185.12.4.2', reason: 'C2 server', recommendation_id: 'r1', created_at: '2026-10-01T10:00:00.000Z' },
        { id: 'a2', kind: InvestigationApprovalKind.DraftValidation, status: InvestigationApprovalStatus.Pending, description: 'Approve the investigation draft', reason: 'Most likely APT28', rejection_reason: 'APT28 is a decoy here', created_at: '2026-10-01T10:00:00.000Z' },
      ],
      enrichment_requests: [{ id: 'q1', entity_id: 'ip-1', connector_id: 'c1', reason: 'Resolve the C2', status: InvestigationEnrichmentRequestStatus.Completed, requested_by: 'engine', created_at: '2026-10-01T10:00:00.000Z' }],
      analyst_feedback: [{ item_type: 'hypothesis', item_ref: 'apt28', decision: 'accepted', comment: 'APT28 confirmed by the SOC', user_id: 'user-1', ts: '2026-10-01T10:00:00.000Z' }],
    } as never);
    const withheld = withheldRunContent(run);
    expect(withheld).toMatchObject({
      name: 'Case Autopilot',
      goal_plan: null,
      evidence: [],
      hypotheses: [],
      timeline: [],
      recommendations: [],
      summary: null,
      report: null,
      report_sources: [],
      outputs: { attributed_candidate_ids: [], observable_ids: {} },
      analyst_feedback: [],
    });
    // The step ledger names the engine run and counts what each source found.
    expect(withheld.steps).toEqual([]);
    expect(JSON.stringify(withheld)).not.toContain('inv-1');
    expect(withheld.enrichment_waves).toEqual([expect.objectContaining({ id: 'w1', delta: [] })]);
    expect(withheld.approvals).toEqual([expect.objectContaining({ id: 'a2', status: InvestigationApprovalStatus.Pending, reason: null, rejection_reason: null })]);
    expect(withheld.enrichment_requests).toEqual([expect.objectContaining({ id: 'q1', status: InvestigationEnrichmentRequestStatus.Completed, reason: null })]);
  });
});
