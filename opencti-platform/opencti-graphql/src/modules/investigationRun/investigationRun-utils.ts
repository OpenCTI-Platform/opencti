/*
Copyright (c) 2021-2025 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Enterprise Edition License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import { InvestigationApprovalKind, InvestigationEvidenceKind } from '../../generated/graphql';
import { extractEntityRepresentativeName } from '../../database/entity-representative';
import { RELATION_CREATED_BY, RELATION_GRANTED_TO, RELATION_OBJECT_MARKING } from '../../schema/stixRefRelationship';
import { ENTITY_TYPE_CAMPAIGN, ENTITY_TYPE_INTRUSION_SET, ENTITY_TYPE_THREAT_ACTOR_GROUP } from '../../schema/stixDomainObject';
import { ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL } from '../threatActorIndividual/threatActorIndividual-types';
import { EMPTY_OUTPUTS, INVESTIGATION_LIMITS, type BasicStoreEntityInvestigationRun, type InvestigationEvidence } from './investigationRun-types';
import type { BasicStoreCommon } from '../../types/store';
import type { AuthUser } from '../../types/user';
import type { BasicStoreSettings } from '../../types/settings';
import {
  isOrganizationUnrestricted,
  isServiceAccountUser,
  isUserHasCapability,
  KNOWLEDGE_ORGANIZATION_RESTRICT,
  MEMBER_ACCESS_ALL,
  MEMBER_ACCESS_RIGHT_ADMIN,
  MEMBER_ACCESS_RIGHT_EDIT,
  MEMBER_ACCESS_RIGHT_USE,
  MEMBER_ACCESS_RIGHT_VIEW,
} from '../../utils/access';
import { DATABASE_ERROR, DRAFT_LOCKED_ERROR, TYPE_LOCK, TYPE_LOCK_ERROR } from '../../config/errors';

// Failures of the platform itself that a later pass may not meet again: the
// database or the search engine briefly unavailable, a lock held elsewhere, a
// draft locked while it is validated, a dropped connection.
const TRANSIENT_ERROR_CODES = [DATABASE_ERROR, TYPE_LOCK, DRAFT_LOCKED_ERROR];
const TRANSIENT_ERROR_NAMES = [TYPE_LOCK_ERROR, 'ConnectionError', 'TimeoutError', 'NoLivingConnectionsError', 'MaxRetriesPerRequestError'];
const TRANSIENT_NETWORK_CODES = ['ECONNRESET', 'ECONNREFUSED', 'ETIMEDOUT', 'EPIPE', 'EAI_AGAIN'];

export const isTransientFailure = (error: unknown): boolean => {
  const chain = [error, (error as { originalError?: unknown } | null)?.originalError, (error as { cause?: unknown } | null)?.cause];
  return chain.some((item) => {
    if (!item || typeof item !== 'object') return false;
    const { name, code, extensions } = item as { name?: unknown; code?: unknown; extensions?: { code?: unknown } };
    return (typeof extensions?.code === 'string' && TRANSIENT_ERROR_CODES.includes(extensions.code))
      || (typeof name === 'string' && TRANSIENT_ERROR_NAMES.includes(name))
      || (typeof code === 'string' && TRANSIENT_NETWORK_CODES.includes(code));
  });
};

// Entity types an incident can be attributed to.
export const ATTRIBUTION_CANDIDATE_TYPES = [
  ENTITY_TYPE_INTRUSION_SET,
  ENTITY_TYPE_THREAT_ACTOR_GROUP,
  ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL,
  ENTITY_TYPE_CAMPAIGN,
];

type RefElement = Record<string, unknown> & {
  internal_id: string;
  entity_type: string;
  standard_id?: string;
  draft_ids?: string[];
};

const idsOf = (resolved: unknown, raw: unknown): string[] => {
  if (Array.isArray(resolved) && resolved.length > 0) {
    return resolved
      .map((item) => (typeof item === 'string' ? item : (item as { internal_id?: string })?.internal_id))
      .filter((id): id is string => typeof id === 'string');
  }
  return Array.isArray(raw) ? raw.filter((id): id is string => typeof id === 'string') : [];
};

// Marking ids of an element, loaded with resolved refs or raw.
export const markingIdsOf = (element: object): string[] => {
  const record = element as Record<string, unknown>;
  return idsOf(record.objectMarking, record[RELATION_OBJECT_MARKING]);
};

// Organizations an element is shared with, loaded with resolved refs or raw.
export const organizationIdsOf = (element: object): string[] => {
  const record = element as Record<string, unknown>;
  return idsOf(record.objectOrganization, record[RELATION_GRANTED_TO]);
};

type RestrictedMember = { id?: string; access_right?: string; groups_restriction_ids?: string[] | null };
const MEMBER_ACCESS_RIGHTS_READ = [MEMBER_ACCESS_RIGHT_VIEW, MEMBER_ACCESS_RIGHT_USE, MEMBER_ACCESS_RIGHT_EDIT, MEMBER_ACCESS_RIGHT_ADMIN];

/**
 * Whether an element is restricted to authorized members. A run and its
 * outputs carry markings and organization sharing but no member restriction,
 * so such an element is never investigated, read into a context or cited.
 * Authorized members that let everyone read the element (the default of a
 * PIR) restrict nothing a run could leak.
 */
export const isMemberRestricted = (element: object | null | undefined): boolean => {
  const members = (element as { restricted_members?: RestrictedMember[] | null } | null | undefined)?.restricted_members;
  if (!Array.isArray(members) || members.length === 0) return false;
  const everyoneReads = members.some((member) => member?.id === MEMBER_ACCESS_ALL
    && !!member.access_right && MEMBER_ACCESS_RIGHTS_READ.includes(member.access_right)
    && (member.groups_restriction_ids ?? []).length === 0);
  return !everyoneReads;
};

/** The elements a run may read or cite: those without a member restriction. */
export const withoutMemberRestricted = <T extends object>(elements: T[]): T[] => elements.filter((element) => !isMemberRestricted(element));

export const isObjectEvidence = (evidence: InvestigationEvidence) => evidence.kind === InvestigationEvidenceKind.OpenctiObject && !!evidence.opencti_id;

/** What a stored run cites: its evidence objects, its hypothesis candidates and its courses of action. */
export const runCitedIds = (run: BasicStoreEntityInvestigationRun): string[] => Array.from(new Set([
  ...(run.evidence ?? []).filter(isObjectEvidence).map((evidence) => evidence.opencti_id as string),
  ...(run.hypotheses ?? []).map((hypothesis) => hypothesis.candidate_id),
  ...(run.recommendations ?? []).flatMap((recommendation) => (recommendation.course_of_action_id ? [recommendation.course_of_action_id] : [])),
])).slice(0, INVESTIGATION_LIMITS.evidence + INVESTIGATION_LIMITS.candidates + INVESTIGATION_LIMITS.coursesOfAction);

/**
 * What the engine received besides what it cites: the context of each start
 * and what the enrichment waves brought, relationship endpoints included. The
 * standard ids reach the live versions of what the waves created in the draft
 * once it is validated.
 */
export const runReceivedIds = (run: BasicStoreEntityInvestigationRun): string[] => Array.from(new Set([
  ...(run.context_ids ?? []),
  ...(run.enrichment_waves ?? []).flatMap((wave) => (wave.delta ?? []).flatMap((object) => [object.id, object.standard_id, object.from_id, object.to_id])),
].filter((id): id is string => !!id)));

/** What a run carries the access of: its subject, its case, what the engine received and what it cites. */
export const runSourceIds = (run: BasicStoreEntityInvestigationRun): string[] => Array.from(new Set([
  run.subject_id,
  run.case_id,
  ...(run.case_ids ?? []),
  ...runReceivedIds(run),
  ...runCitedIds(run),
].filter((id): id is string => !!id)));

export const WITHHELD_RUN_NAME = 'Case Autopilot';

/**
 * Everything a run derived from what it read, emptied: its name, which quotes
 * its subject, the engine's text, its step ledger, which names the engine runs and what each source found,
 * the conclusion OpenCTI scored from it, the references to its outputs, what its
 * enrichment waves brought, the analyst feedback on its findings, and the
 * approvals and requests quoting any of it (a recommendation approval quotes
 * its recommendation; the other records keep their decision, not their
 * reason). Withheld once the run is stopped at an access boundary, and from a
 * reader while one of its sources is beyond that reader's access.
 */
export const withheldRunContent = (run: BasicStoreEntityInvestigationRun) => ({
  name: WITHHELD_RUN_NAME,
  goal_plan: null,
  steps: [],
  evidence: [],
  hypotheses: [],
  timeline: [],
  recommendations: [],
  summary: null,
  report: null,
  report_sources: [],
  outputs: EMPTY_OUTPUTS,
  enrichment_waves: (run.enrichment_waves ?? []).map((wave) => ({ ...wave, delta: [] })),
  analyst_feedback: [],
  approvals: (run.approvals ?? [])
    .filter((approval) => approval.kind !== InvestigationApprovalKind.Recommendation)
    .map((approval) => ({ ...approval, reason: null, rejection_reason: null })),
  enrichment_requests: (run.enrichment_requests ?? []).map((request) => ({ ...request, reason: null })),
});

/**
 * Restrictive organization sharing: what is written from several elements is
 * shared only with the organizations every one of them is shared with, so
 * citing an object never widens who can read it. An element of a type that
 * is visible whatever the organization does not restrict.
 */
export const intersectOrganizationIds = (base: string[], elements: object[]): string[] => {
  return elements.reduce<string[]>((current, element) => {
    const { entity_type: entityType } = element as { entity_type?: string };
    if (!entityType || isOrganizationUnrestricted(element as BasicStoreCommon)) return current;
    const sharing = organizationIdsOf(element);
    return current.filter((id) => sharing.includes(id));
  }, Array.from(new Set(base)));
};

/**
 * Whether creating an element as `user` with the `allowed` organizations would
 * share it more widely, by the rule the platform applies at creation: the
 * requested organizations when the user may restrict, otherwise the user's own
 * organizations when the user is outside the platform organization.
 */
export const isCreationSharingWidened = (user: AuthUser, settings: BasicStoreSettings, insidePlatformOrganization: boolean, allowed: string[]) => {
  if (!settings.platform_organization) return false;
  if (isUserHasCapability(user, KNOWLEDGE_ORGANIZATION_RESTRICT) && allowed.length > 0) return false;
  if (!insidePlatformOrganization || (isServiceAccountUser(user) && (user.organizations ?? []).length > 0)) {
    return (user.organizations ?? []).some((organization) => !allowed.includes(organization.internal_id));
  }
  return false;
};

export const authorIdOf = (element: object): string | null => {
  const record = element as Record<string, unknown>;
  const resolved = record.createdBy as { internal_id?: string } | undefined;
  if (resolved?.internal_id) return resolved.internal_id;
  const raw = record[RELATION_CREATED_BY];
  return typeof raw === 'string' ? raw : null;
};

const dateOf = (value: unknown): string | null => {
  if (!value) return null;
  const date = new Date(value as string);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
};

export const isElementInDraft = (element: object, draftId: string | null | undefined): boolean => {
  const record = element as RefElement;
  return !!draftId && Array.isArray(record.draft_ids) && record.draft_ids.includes(draftId);
};

export const representativeNameOf = (element: object): string | null => {
  const name = extractEntityRepresentativeName(element as RefElement) as string | undefined;
  return name ? String(name).slice(0, 500) : null;
};

// An OpenCTI object as evidence (shared shape), with the attributes the ACH
// helper weights it by.
export const evidenceFromElement = (
  element: object,
  opts: { draftId?: string | null; authorReliability?: string | null; investigationId?: string | null } = {},
): InvestigationEvidence => {
  const record = element as RefElement;
  const confidence = typeof record.confidence === 'number' ? record.confidence : null;
  return {
    id: record.internal_id,
    investigation_id: opts.investigationId ?? null,
    n: null,
    kind: InvestigationEvidenceKind.OpenctiObject,
    label: representativeNameOf(record) ?? record.internal_id,
    href: null,
    quote: null,
    opencti_id: record.internal_id,
    standard_id: record.standard_id ?? null,
    entity_type: record.entity_type,
    in_draft: isElementInDraft(record, opts.draftId),
    confidence,
    author_reliability: opts.authorReliability ?? null,
    created: dateOf(record.created),
    first_seen: dateOf(record.first_seen ?? record.start_time),
    last_seen: dateOf(record.last_seen ?? record.stop_time),
  };
};
