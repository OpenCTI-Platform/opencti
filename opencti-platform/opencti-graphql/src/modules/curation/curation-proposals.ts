import * as R from 'ramda';
import { createHash } from 'node:crypto';
import type { AuthContext } from '../../types/user';
import type { BasicStoreBase, BasicStoreEntity } from '../../types/store';
import type { BasicStoreSettings } from '../../types/settings';
import { createEntity, deleteElementById, patchAttribute, updateAttribute } from '../../database/middleware';
import { fullEntitiesList, internalFindByIds, storeLoadById } from '../../database/middleware-loader';
import { getEntityFromCache } from '../../database/cache';
import { ENTITY_TYPE_SETTINGS } from '../../schema/internalObject';
import { RELATION_GRANTED_TO, RELATION_OBJECT_MARKING } from '../../schema/stixRefRelationship';
import { CURATION_MANAGER_USER, SYSTEM_USER } from '../../utils/access';
import { type EditInput, EditOperation, FilterMode, FilterOperator } from '../../generated/graphql';
import { INPUT_GRANTED_REFS, INPUT_MARKINGS } from '../../schema/general';
import { isEnterpriseEditionFromSettings } from '../../enterprise-edition/ee';
import { addCurationProposalCreatedCount, addCurationProposalRevertedCount } from '../../manager/telemetryManager';
import { logApp } from '../../config/conf';
import {
  ACTION_ACKNOWLEDGE,
  type BasicStoreEntityCurationProposal,
  type CurationSettings,
  ENTITY_TYPE_CURATION_PROPOSAL,
  PROPOSAL_KIND_ALIAS,
  PROPOSAL_KIND_CONTRADICTION,
  PROPOSAL_KIND_FIELD_PRECEDENCE,
  PROPOSAL_KIND_MERGE,
  PROPOSAL_KIND_RELATIONSHIP_CONFLICT,
  PROPOSAL_KIND_STALE,
  PROPOSAL_KIND_TYPE_MISMATCH,
  PROPOSAL_STATUS_ACCEPTED,
  PROPOSAL_STATUS_AUTO_APPLIED,
  PROPOSAL_STATUS_OPEN,
  PROPOSAL_STATUS_REJECTED,
  PROPOSAL_STATUS_REVERTED,
  type ProposalDraft,
} from './curation-types';
import { buildPairFingerprint, buildProposalFingerprint, isInAmbiguousBand } from './curation-normalization';
import { withProposalFingerprintLock, withProposalTransitionLock } from './curation-locks';

const PAIR_KINDS = [PROPOSAL_KIND_MERGE, PROPOSAL_KIND_TYPE_MISMATCH];

const shortHash = (value: unknown) => createHash('sha256').update(JSON.stringify(value ?? null)).digest('hex').slice(0, 16);

/**
 * A fingerprint identifies "the same finding": a re-detection refreshes the open proposal, and a rejected finding is
 * never proposed again, while a fixed one that comes back is. Some kinds carry a discriminator so that a genuinely new
 * finding on the same subjects is new.
 */
export const draftFingerprint = (draft: ProposalDraft): string => {
  const subjectIds = draft.subjects.map((subject) => subject.id);
  const payload = draft.action_payload ?? {};
  switch (draft.kind) {
    case PROPOSAL_KIND_ALIAS:
      return buildProposalFingerprint(draft.kind, subjectIds, shortHash([...(payload.aliases as string[] ?? [])].map((a) => a.toLowerCase()).sort()));
    case PROPOSAL_KIND_RELATIONSHIP_CONFLICT:
      return buildProposalFingerprint(draft.kind, subjectIds, shortHash([payload.previous, payload.current]));
    case PROPOSAL_KIND_STALE:
      return buildProposalFingerprint(draft.kind, subjectIds, String(draft.evidence[0]?.details ? JSON.parse(draft.evidence[0].details).last_activity ?? '' : ''));
    case PROPOSAL_KIND_CONTRADICTION:
      return buildProposalFingerprint(draft.kind, subjectIds, draft.recommended_action);
    case PROPOSAL_KIND_FIELD_PRECEDENCE:
      return buildProposalFingerprint(draft.kind, subjectIds, shortHash([payload.key, payload.value]));
    default:
      return buildProposalFingerprint(draft.kind, subjectIds);
  }
};

export const draftPairFingerprints = (draft: ProposalDraft): string[] => {
  if (!PAIR_KINDS.includes(draft.kind)) return [];
  const ids = draft.subjects.map((subject) => subject.id);
  const fingerprints: string[] = [];
  for (let i = 0; i < ids.length; i += 1) {
    for (let j = i + 1; j < ids.length; j += 1) {
      fingerprints.push(buildPairFingerprint([ids[i], ids[j]]));
    }
  }
  return fingerprints;
};

/**
 * The organizations every restricted element is shared with (an element shared with no organization restricts
 * nothing). When the restricted elements share no organization, only the platform organization keeps access.
 */
export const intersectGrantedOrganizations = (grantedSets: string[][], platformOrganizationId?: string | null): string[] => {
  const restrictedSets = grantedSets.filter((set) => set.length > 0);
  if (restrictedSets.length === 0) return [];
  const shared = R.uniq(restrictedSets.reduce((acc, set) => acc.filter((id) => set.includes(id))));
  if (shared.length === 0 && platformOrganizationId) return [platformOrganizationId];
  return shared;
};

/**
 * Visibility of a proposal derives from the elements it reveals (its subjects, and the relationships its action
 * names): it carries the union of their markings (a reader needs all of them) and the organizations every restricted
 * element is shared with, so a proposal never reveals a subject or a relationship to a user who cannot read it.
 */
export const computeSubjectRestrictions = (subjects: BasicStoreBase[], platformOrganizationId?: string | null) => {
  const markingIds = R.uniq(subjects.flatMap((subject) => ((subject as any)[RELATION_OBJECT_MARKING] ?? []) as string[]));
  const grantedSets = subjects.map((subject) => ((subject as any)[RELATION_GRANTED_TO] ?? []) as string[]);
  return { markingIds, organizationIds: intersectGrantedOrganizations(grantedSets, platformOrganizationId) };
};

const parseActionPayload = (payload: unknown): Record<string, unknown> | null => {
  let parsed = payload;
  if (typeof payload === 'string') {
    try {
      parsed = JSON.parse(payload);
    } catch {
      return null;
    }
  }
  return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed as Record<string, unknown> : null;
};

/**
 * The relationships an action payload names: the attributions in conflict of an attribution contradiction, the
 * relationship whose procedure is kept. The proposal shows them in its evidence and acts on them.
 */
export const payloadRelationshipIds = (payload: unknown): string[] => {
  const record = parseActionPayload(payload);
  if (!record) return [];
  const ids: string[] = [];
  if (typeof record.relationship_id === 'string') ids.push(record.relationship_id);
  if (Array.isArray(record.relationships)) {
    record.relationships.forEach((relationship) => {
      const relationshipId = (relationship as { relationship_id?: unknown } | null)?.relationship_id;
      if (typeof relationshipId === 'string') ids.push(relationshipId);
    });
  }
  return R.uniq(ids);
};

/** The names an alias proposal adds to its target: the names a public taxonomy gives the entity that it does not carry yet. */
export const payloadAliases = (payload: unknown): string[] => {
  const aliases = parseActionPayload(payload)?.aliases;
  return Array.isArray(aliases) ? aliases.filter((alias): alias is string => typeof alias === 'string' && alias.length > 0) : [];
};

/** The relationships named by the action of a proposal that are not its subjects; a deleted one restricts nothing. */
const loadPayloadRelationships = async (context: AuthContext, subjectIds: string[], payload: unknown) => {
  const relationshipIds = payloadRelationshipIds(payload).filter((id) => !subjectIds.includes(id));
  if (relationshipIds.length === 0) return [];
  return internalFindByIds(context, SYSTEM_USER, relationshipIds, { baseData: true }) as Promise<BasicStoreBase[]>;
};

const findByFingerprints = async (context: AuthContext, fingerprints: string[]) => {
  if (fingerprints.length === 0) return [];
  return fullEntitiesList<BasicStoreEntityCurationProposal>(context, SYSTEM_USER, [ENTITY_TYPE_CURATION_PROPOSAL], {
    filters: {
      mode: FilterMode.And,
      filters: [{ key: ['proposal_fingerprint'], values: fingerprints, operator: FilterOperator.Eq }],
      filterGroups: [],
    },
    noFiltersChecking: true,
  });
};

export const findSuppressingProposals = async (context: AuthContext, pairFingerprints: string[]) => {
  if (pairFingerprints.length === 0) return [];
  return fullEntitiesList<BasicStoreEntityCurationProposal>(context, SYSTEM_USER, [ENTITY_TYPE_CURATION_PROPOSAL], {
    filters: {
      mode: FilterMode.And,
      filters: [
        { key: ['pair_fingerprints'], values: pairFingerprints, operator: FilterOperator.Eq },
        { key: ['proposal_status'], values: [PROPOSAL_STATUS_REJECTED, PROPOSAL_STATUS_REVERTED], operator: FilterOperator.Eq },
      ],
      filterGroups: [],
    },
    noFiltersChecking: true,
  });
};

/**
 * Whether a decided proposal keeps its finding from being proposed again: a rejection, a revert, or an accepted
 * acknowledgement say the finding is fine as it is. A change that was applied (a merge, a date fix, a revocation...)
 * does not: when the detector finds the same state again, it came back, and a new proposal is raised.
 */
export const isSuppressingDecision = (proposal: Pick<BasicStoreEntityCurationProposal, 'proposal_status' | 'recommended_action'>) => {
  if (proposal.proposal_status === PROPOSAL_STATUS_REJECTED || proposal.proposal_status === PROPOSAL_STATUS_REVERTED) return true;
  const applied = proposal.proposal_status === PROPOSAL_STATUS_ACCEPTED || proposal.proposal_status === PROPOSAL_STATUS_AUTO_APPLIED;
  return applied && proposal.recommended_action === ACTION_ACKNOWLEDGE;
};

/**
 * Close an applied proposal as reverted. Its revert and an unmerge of its merge record both close it: the reversion is
 * counted once, by whichever closes it first.
 */
export const markProposalReverted = async (context: AuthContext, proposalId: string): Promise<BasicStoreEntityCurationProposal | null> => {
  const current = await storeLoadById<BasicStoreEntityCurationProposal>(context, SYSTEM_USER, proposalId, ENTITY_TYPE_CURATION_PROPOSAL);
  if (!current || current.proposal_status === PROPOSAL_STATUS_REVERTED) return current ?? null;
  const { element } = await patchAttribute(context, SYSTEM_USER, proposalId, ENTITY_TYPE_CURATION_PROPOSAL, { proposal_status: PROPOSAL_STATUS_REVERTED });
  addCurationProposalRevertedCount();
  return element as unknown as BasicStoreEntityCurationProposal;
};

export interface PersistResult {
  proposal: BasicStoreEntityCurationProposal | null;
  created: boolean;
  suppressed: boolean;
}

const proposalName = (draft: ProposalDraft) => {
  const names = draft.subjects.map((subject) => subject.name || subject.id).join(' / ');
  return names.length > 250 ? `${names.slice(0, 247)}...` : names;
};

const sameIds = (left: string[], right: string[]) => left.length === right.length && left.every((id) => right.includes(id));

/** What an adjudication judges: a proposal whose subjects, names, finding or proposed change differ is another case. */
export const adjudicatedContent = (
  proposal: Pick<BasicStoreEntityCurationProposal, 'subject_ids' | 'subject_names' | 'confidence_score' | 'curation_evidence' | 'action_payload'>,
) => JSON.stringify([proposal.subject_ids, proposal.subject_names, proposal.confidence_score, proposal.curation_evidence, proposal.action_payload ?? null]);

/** A payload as JSON keeps it: key order and undefined members never make two payloads differ. */
const canonicalPayload = (payload: unknown) => {
  const parsed = parseActionPayload(payload);
  return parsed ? JSON.parse(JSON.stringify(parsed)) : null;
};

/**
 * What a new detection of an open finding changes: the finding itself (confidence, evidence), or what accepting it
 * executes (survivor, action, payload), which a duplicate scan recomputes from the current subjects.
 */
export const refreshedContentChanges = (
  existing: Pick<BasicStoreEntityCurationProposal, 'confidence_score' | 'curation_evidence' | 'target_id' | 'recommended_action' | 'action_payload'>,
  draft: Pick<ProposalDraft, 'confidence' | 'evidence' | 'target_id' | 'recommended_action' | 'action_payload'>,
) => ({
  finding: Math.abs(existing.confidence_score - draft.confidence) > 0.001
    || JSON.stringify(existing.curation_evidence) !== JSON.stringify(draft.evidence),
  executable: (existing.target_id ?? null) !== (draft.target_id ?? null)
    || existing.recommended_action !== draft.recommended_action
    || !R.equals(canonicalPayload(existing.action_payload), canonicalPayload(draft.action_payload)),
});

/**
 * Refresh of an open proposal found again: its restrictions and subject names follow the current subjects, so a
 * subject that gained a marking or an organization restriction since is never exposed through an older proposal, and
 * what accepting it executes follows the detection, so neither an analyst nor a policy applies an outdated survivor. A
 * refreshed finding or recommendation drops its adjudication, which judged the previous one: the proposal is
 * adjudicated again before a policy requiring the Curator's agreement can apply it.
 */
const refreshProposal = async (
  context: AuthContext,
  existing: BasicStoreEntityCurationProposal,
  draft: ProposalDraft,
  inBand: boolean,
): Promise<PersistResult> => {
  const subjects = await internalFindByIds(context, SYSTEM_USER, existing.subject_ids, { baseData: true }) as BasicStoreBase[];
  if (subjects.length !== existing.subject_ids.length) {
    logApp.debug('[CURATION] Proposal subjects disappeared before refresh, keeping the proposal', { id: existing.internal_id });
    return { proposal: existing, created: false, suppressed: false };
  }
  const relationships = await loadPayloadRelationships(context, existing.subject_ids, draft.action_payload);
  const settingsEntity = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  const { markingIds, organizationIds } = computeSubjectRestrictions([...subjects, ...relationships], settingsEntity?.platform_organization);
  const restrictionsChanged = !sameIds(markingIds, ((existing as any)[RELATION_OBJECT_MARKING] ?? []) as string[])
    || !sameIds(organizationIds, ((existing as any)[RELATION_GRANTED_TO] ?? []) as string[]);
  const subjectsById = new Map(subjects.map((subject) => [subject.internal_id, subject]));
  const subjectNames = existing.subject_ids.map((id, index) => ((subjectsById.get(id) as { name?: string } | undefined)?.name ?? existing.subject_names[index]));
  const namesChanged = JSON.stringify(subjectNames) !== JSON.stringify(existing.subject_names);
  const { finding: findingChanged, executable: executableChanged } = refreshedContentChanges(existing, draft);
  // The band settings may have moved an unchanged finding in or out of the band the Curator and the counters read.
  const bandChanged = (existing.in_ambiguous_band ?? false) !== inBand;
  if (!restrictionsChanged && !namesChanged && !findingChanged && !executableChanged && !bandChanged) {
    return { proposal: existing, created: false, suppressed: false };
  }
  if (restrictionsChanged) {
    await updateAttribute(context, CURATION_MANAGER_USER, existing.internal_id, ENTITY_TYPE_CURATION_PROPOSAL, [
      { key: INPUT_MARKINGS, value: markingIds, operation: EditOperation.Replace },
      { key: INPUT_GRANTED_REFS, value: organizationIds, operation: EditOperation.Replace },
    ]);
  }
  const joinedNames = subjectNames.join(' / ');
  const { element: updated } = await patchAttribute(context, CURATION_MANAGER_USER, existing.internal_id, ENTITY_TYPE_CURATION_PROPOSAL, {
    name: joinedNames.length > 250 ? `${joinedNames.slice(0, 247)}...` : joinedNames,
    subject_names: subjectNames,
    confidence_score: draft.confidence,
    in_ambiguous_band: inBand,
    curation_evidence: draft.evidence,
    detector: draft.detector,
    target_id: draft.target_id ?? null,
    recommended_action: draft.recommended_action,
    action_payload: draft.action_payload ?? null,
    ...((namesChanged || findingChanged || executableChanged) && (existing.curation_adjudication || existing.adjudication_requested_at)
      ? { curation_adjudication: null, adjudication_requested_at: null }
      : {}),
  });
  return { proposal: updated as unknown as BasicStoreEntityCurationProposal, created: false, suppressed: false };
};

/**
 * Keep the restrictions of the open proposals about these subjects in line with them when a subject, or a relationship
 * between subjects, is reclassified, whether curation is enabled or not: a proposal never stays readable by a user who
 * lost access to one of its subjects or to a relationship its action names. A proposal whose subjects are not all
 * there any more is only ever narrowed, since it still names the missing ones.
 */
export const refreshProposalRestrictions = async (context: AuthContext, subjectIds: string[]) => {
  if (subjectIds.length === 0) return 0;
  const proposals = await fullEntitiesList<BasicStoreEntityCurationProposal>(context, SYSTEM_USER, [ENTITY_TYPE_CURATION_PROPOSAL], {
    filters: {
      mode: FilterMode.And,
      filters: [
        { key: ['subject_ids'], values: subjectIds, operator: FilterOperator.Eq },
        { key: ['proposal_status'], values: [PROPOSAL_STATUS_OPEN], operator: FilterOperator.Eq },
      ],
      filterGroups: [],
    },
    noFiltersChecking: true,
  });
  if (proposals.length === 0) return 0;
  const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  let refreshed = 0;
  for (let index = 0; index < proposals.length; index += 1) {
    const proposal = proposals[index];
    const currentMarkings = ((proposal as Record<string, any>)[RELATION_OBJECT_MARKING] ?? []) as string[];
    const currentOrganizations = ((proposal as Record<string, any>)[RELATION_GRANTED_TO] ?? []) as string[];
    const subjects = await internalFindByIds(context, SYSTEM_USER, proposal.subject_ids, { baseData: true }) as BasicStoreBase[];
    const relationships = await loadPayloadRelationships(context, proposal.subject_ids, proposal.action_payload);
    const complete = subjects.length === proposal.subject_ids.length;
    const revealed = [...subjects, ...relationships];
    const computed = computeSubjectRestrictions(revealed, settings?.platform_organization);
    const markingIds = complete ? computed.markingIds : R.uniq([...currentMarkings, ...computed.markingIds]);
    const subjectOrganizationSets = revealed.map((element) => ((element as Record<string, any>)[RELATION_GRANTED_TO] ?? []) as string[]);
    const organizationIds = complete
      ? computed.organizationIds
      : intersectGrantedOrganizations([currentOrganizations, ...subjectOrganizationSets], settings?.platform_organization);
    const inputs: EditInput[] = [];
    if (!sameIds(markingIds, currentMarkings)) {
      inputs.push({ key: INPUT_MARKINGS, value: markingIds, operation: EditOperation.Replace });
    }
    // Organization sharing is an Enterprise Edition capability: without it, the platform neither applies nor accepts it.
    if (isEnterpriseEditionFromSettings(settings) && !sameIds(organizationIds, currentOrganizations)) {
      inputs.push({ key: INPUT_GRANTED_REFS, value: organizationIds, operation: EditOperation.Replace });
    }
    if (inputs.length > 0) {
      await updateAttribute(context, CURATION_MANAGER_USER, proposal.internal_id, ENTITY_TYPE_CURATION_PROPOSAL, inputs);
      refreshed += 1;
    }
  }
  return refreshed;
};

/**
 * The open alias proposals an alias proposal of the same entity replaces: an alias proposal names every catalogue name
 * the entity lacks when it is raised, so an older one (other names, other catalogues, or one per catalogue as raised by
 * earlier versions) describes a state that is gone. One an acceptance started to apply stays, so that accepting it
 * again records what was done.
 */
export const supersededAliasProposals = (
  open: Array<Pick<BasicStoreEntityCurationProposal, 'internal_id' | 'proposal_kind' | 'proposal_status' | 'proposal_fingerprint' | 'subject_ids' | 'application_started_at'>>,
  current: Pick<BasicStoreEntityCurationProposal, 'internal_id' | 'proposal_fingerprint' | 'subject_ids'>,
) => open.filter((proposal) => proposal.proposal_kind === PROPOSAL_KIND_ALIAS
  && proposal.proposal_status === PROPOSAL_STATUS_OPEN
  && !proposal.application_started_at
  && proposal.internal_id !== current.internal_id
  && proposal.proposal_fingerprint !== current.proposal_fingerprint
  && proposal.subject_ids.length === 1
  && proposal.subject_ids[0] === current.subject_ids[0]);

// Each is read again under its transition lock: a proposal being decided, or decided since, is never removed.
const removeSupersededAliasProposals = async (context: AuthContext, current: BasicStoreEntityCurationProposal) => {
  const open = await findOpenProposalsForSubjects(context, current.subject_ids, [PROPOSAL_KIND_ALIAS]);
  const superseded = supersededAliasProposals(open, current);
  for (let index = 0; index < superseded.length; index += 1) {
    const { internal_id: id } = superseded[index];
    await withProposalTransitionLock(id, async () => {
      const [reloaded] = await internalFindByIds(context, SYSTEM_USER, [id]) as BasicStoreEntityCurationProposal[];
      if (reloaded?.proposal_status !== PROPOSAL_STATUS_OPEN || reloaded.application_started_at) return;
      await deleteElementById(context, SYSTEM_USER, id, ENTITY_TYPE_CURATION_PROPOSAL);
    });
  }
};

/** The open proposals to retire: they name a subject that no longer exists, and no acceptance has started writing. */
export const proposalsOfMissingSubjects = (
  open: Array<Pick<BasicStoreEntityCurationProposal, 'internal_id' | 'subject_ids' | 'application_started_at'>>,
  existingIds: Set<string>,
) => open.filter((proposal) => !proposal.application_started_at && proposal.subject_ids.some((id) => !existingIds.has(id)));

/**
 * Remove the open proposals about deleted entities, whether curation is enabled or not: they could no longer be applied,
 * yet they would stay listed and counted. A subject restored since (an unmerge, the trash) keeps its proposals, and one
 * an acceptance started to apply stays, so that accepting it again records what was done.
 */
export const retireProposalsOfDeletedSubjects = async (context: AuthContext, deletedIds: string[]) => {
  const open = await findOpenProposalsForSubjects(context, deletedIds);
  if (open.length === 0) return 0;
  const subjectIds = R.uniq(open.flatMap((proposal) => proposal.subject_ids));
  const existing = await internalFindByIds(context, SYSTEM_USER, subjectIds, { baseData: true }) as BasicStoreBase[];
  const retired = proposalsOfMissingSubjects(open, new Set(existing.map((element) => element.internal_id)));
  let count = 0;
  for (let index = 0; index < retired.length; index += 1) {
    const { internal_id: id } = retired[index];
    await withProposalTransitionLock(id, async () => {
      const [reloaded] = await internalFindByIds(context, SYSTEM_USER, [id]) as BasicStoreEntityCurationProposal[];
      if (reloaded?.proposal_status !== PROPOSAL_STATUS_OPEN || reloaded.application_started_at) return;
      await deleteElementById(context, SYSTEM_USER, id, ENTITY_TYPE_CURATION_PROPOSAL);
      count += 1;
    });
  }
  return count;
};

const persistLockedProposalDraft = async (
  context: AuthContext,
  settings: CurationSettings,
  draft: ProposalDraft,
  fingerprint: string,
  opts: { policyId?: string | null },
): Promise<PersistResult> => {
  const pairFingerprints = draftPairFingerprints(draft);
  const sameFindings = await findByFingerprints(context, [fingerprint]);
  const existing = sameFindings.find((proposal) => proposal.proposal_status === PROPOSAL_STATUS_OPEN);
  const suppressing = existing ? undefined : sameFindings.find((proposal) => isSuppressingDecision(proposal));
  if (suppressing) {
    return { proposal: suppressing, created: false, suppressed: true };
  }
  if (!existing && pairFingerprints.length > 0) {
    const suppressing = await findSuppressingProposals(context, pairFingerprints);
    if (suppressing.length > 0) {
      return { proposal: null, created: false, suppressed: true };
    }
  }
  const inBand = isInAmbiguousBand(draft.confidence, settings.ambiguous_band_min, settings.ambiguous_band_max);
  if (existing) {
    // A proposal being applied keeps the content its application started from, so a retry applies or records that one.
    const refreshed = existing.application_started_at
      ? { proposal: existing, created: false, suppressed: false }
      : await refreshProposal(context, existing, draft, inBand);
    if (draft.kind === PROPOSAL_KIND_ALIAS) await removeSupersededAliasProposals(context, existing);
    return refreshed;
  }
  const subjectIds = draft.subjects.map((subject) => subject.id);
  const subjects = await internalFindByIds(context, SYSTEM_USER, subjectIds, { baseData: true }) as BasicStoreBase[];
  if (subjects.length !== subjectIds.length) {
    logApp.debug('[CURATION] Proposal subjects disappeared before persistence, skipping', { subjectIds });
    return { proposal: null, created: false, suppressed: false };
  }
  // `subject_ids` always holds internal ids (consumers match proposals to entities by internal id), whatever id a
  // detector used to name a subject.
  const subjectsById = new Map<string, BasicStoreBase>();
  subjects.forEach((subject) => {
    subjectsById.set(subject.internal_id, subject);
    subjectsById.set(subject.standard_id, subject);
  });
  const subjectInternalIds = subjectIds.map((id) => subjectsById.get(id)?.internal_id ?? id);
  const relationships = await loadPayloadRelationships(context, subjectInternalIds, draft.action_payload);
  const settingsEntity = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  const { markingIds, organizationIds } = computeSubjectRestrictions([...subjects, ...relationships], settingsEntity?.platform_organization);
  const input = {
    name: proposalName(draft),
    proposal_kind: draft.kind,
    proposal_status: PROPOSAL_STATUS_OPEN,
    proposal_fingerprint: fingerprint,
    pair_fingerprints: pairFingerprints,
    confidence_score: draft.confidence,
    in_ambiguous_band: inBand,
    detector: draft.detector,
    subject_ids: subjectInternalIds,
    subject_types: draft.subjects.map((subject) => subject.entity_type),
    subject_names: draft.subjects.map((subject) => subject.name || subject.id),
    target_id: draft.target_id ?? null,
    recommended_action: draft.recommended_action,
    action_payload: draft.action_payload ?? null,
    curation_evidence: draft.evidence,
    policy_id: opts.policyId ?? null,
    objectMarking: markingIds,
    objectOrganization: organizationIds,
  };
  const created = await createEntity(context, CURATION_MANAGER_USER, input, ENTITY_TYPE_CURATION_PROPOSAL) as unknown as BasicStoreEntityCurationProposal;
  addCurationProposalCreatedCount();
  if (draft.kind === PROPOSAL_KIND_ALIAS) await removeSupersededAliasProposals(context, created);
  return { proposal: created, created: true, suppressed: false };
};

/**
 * Create a proposal from a detector draft, or refresh the matching open one. Rejected, reverted or acknowledged
 * findings are never proposed again (see isSuppressingDecision). The stream handler and the scheduled scans detect the
 * same findings concurrently: the lookup by fingerprint and the creation run under the fingerprint lock, so a finding
 * never gets two open proposals.
 */
export const persistProposalDraft = async (
  context: AuthContext,
  settings: CurationSettings,
  draft: ProposalDraft,
  opts: { policyId?: string | null } = {},
): Promise<PersistResult> => {
  const fingerprint = draftFingerprint(draft);
  return withProposalFingerprintLock(fingerprint, () => persistLockedProposalDraft(context, settings, draft, fingerprint, opts));
};

/**
 * Open proposals involving one of the given entities (used by entity overviews and policy safety checks).
 */
export const findOpenProposalsForSubjects = async (context: AuthContext, subjectIds: string[], kinds?: string[]) => {
  if (subjectIds.length === 0) return [];
  const filters = [
    { key: ['subject_ids'], values: subjectIds, operator: FilterOperator.Eq },
    { key: ['proposal_status'], values: [PROPOSAL_STATUS_OPEN], operator: FilterOperator.Eq },
  ];
  if (kinds && kinds.length > 0) {
    filters.push({ key: ['proposal_kind'], values: kinds, operator: FilterOperator.Eq });
  }
  return fullEntitiesList<BasicStoreEntityCurationProposal>(context, SYSTEM_USER, [ENTITY_TYPE_CURATION_PROPOSAL], {
    filters: { mode: FilterMode.And, filters, filterGroups: [] },
    noFiltersChecking: true,
  });
};

export type ProposalSubjectEntity = BasicStoreEntity & Record<string, any>;
