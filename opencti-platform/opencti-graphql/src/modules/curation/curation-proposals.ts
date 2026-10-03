import * as R from 'ramda';
import { createHash } from 'node:crypto';
import type { AuthContext } from '../../types/user';
import type { BasicStoreBase, BasicStoreEntity } from '../../types/store';
import type { BasicStoreSettings } from '../../types/settings';
import { createEntity, patchAttribute } from '../../database/middleware';
import { fullEntitiesList, internalFindByIds } from '../../database/middleware-loader';
import { getEntityFromCache } from '../../database/cache';
import { ENTITY_TYPE_SETTINGS } from '../../schema/internalObject';
import { RELATION_GRANTED_TO, RELATION_OBJECT_MARKING } from '../../schema/stixRefRelationship';
import { CURATION_MANAGER_USER, SYSTEM_USER } from '../../utils/access';
import { FilterMode, FilterOperator } from '../../generated/graphql';
import { addCurationProposalCreatedCount } from '../../manager/telemetryManager';
import { logApp } from '../../config/conf';
import {
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
  PROPOSAL_STATUS_OPEN,
  PROPOSAL_STATUS_REJECTED,
  PROPOSAL_STATUS_REVERTED,
  type ProposalDraft,
} from './curation-types';
import { buildPairFingerprint, buildProposalFingerprint, isInAmbiguousBand } from './curation-normalization';

const PAIR_KINDS = [PROPOSAL_KIND_MERGE, PROPOSAL_KIND_TYPE_MISMATCH];

const shortHash = (value: unknown) => createHash('sha256').update(JSON.stringify(value ?? null)).digest('hex').slice(0, 16);

/**
 * A fingerprint identifies "the same finding": a re-detection refreshes the open proposal, and a rejected finding is
 * never proposed again. Some kinds carry a discriminator so that a genuinely new finding on the same subjects is new.
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
 * Visibility of a proposal derives from its subjects: it carries the union of their markings (a reader needs all of
 * them) and the organizations every restricted subject is shared with, so a proposal never reveals the name of a
 * subject to a user who cannot read it.
 */
export const computeSubjectRestrictions = (subjects: BasicStoreBase[], platformOrganizationId?: string | null) => {
  const markingIds = R.uniq(subjects.flatMap((subject) => ((subject as any)[RELATION_OBJECT_MARKING] ?? []) as string[]));
  const grantedSets = subjects.map((subject) => ((subject as any)[RELATION_GRANTED_TO] ?? []) as string[]).filter((set) => set.length > 0);
  let organizationIds: string[] = [];
  if (grantedSets.length > 0) {
    organizationIds = grantedSets.reduce((acc, set) => acc.filter((id) => set.includes(id)));
    if (organizationIds.length === 0 && platformOrganizationId) {
      organizationIds = [platformOrganizationId];
    }
  }
  return { markingIds, organizationIds };
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

export interface PersistResult {
  proposal: BasicStoreEntityCurationProposal | null;
  created: boolean;
  suppressed: boolean;
}

const proposalName = (draft: ProposalDraft) => {
  const names = draft.subjects.map((subject) => subject.name || subject.id).join(' / ');
  return names.length > 250 ? `${names.slice(0, 247)}...` : names;
};

/**
 * Create a proposal from a detector draft, or refresh the matching open one. Rejected, reverted or applied findings
 * are never proposed again.
 */
export const persistProposalDraft = async (
  context: AuthContext,
  settings: CurationSettings,
  draft: ProposalDraft,
  opts: { policyId?: string | null } = {},
): Promise<PersistResult> => {
  const fingerprint = draftFingerprint(draft);
  const pairFingerprints = draftPairFingerprints(draft);
  const [existing] = await findByFingerprints(context, [fingerprint]);
  if (existing && existing.proposal_status !== PROPOSAL_STATUS_OPEN) {
    return { proposal: existing, created: false, suppressed: true };
  }
  if (!existing && pairFingerprints.length > 0) {
    const suppressing = await findSuppressingProposals(context, pairFingerprints);
    if (suppressing.length > 0) {
      return { proposal: null, created: false, suppressed: true };
    }
  }
  const inBand = isInAmbiguousBand(draft.confidence, settings.ambiguous_band_min, settings.ambiguous_band_max);
  if (existing) {
    const changed = Math.abs(existing.confidence_score - draft.confidence) > 0.001
      || JSON.stringify(existing.curation_evidence) !== JSON.stringify(draft.evidence);
    if (!changed) {
      return { proposal: existing, created: false, suppressed: false };
    }
    const { element: updated } = await patchAttribute(context, CURATION_MANAGER_USER, existing.internal_id, ENTITY_TYPE_CURATION_PROPOSAL, {
      confidence_score: draft.confidence,
      in_ambiguous_band: inBand,
      curation_evidence: draft.evidence,
      detector: draft.detector,
      action_payload: draft.action_payload ?? null,
    });
    return { proposal: updated as unknown as BasicStoreEntityCurationProposal, created: false, suppressed: false };
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
  const settingsEntity = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  const { markingIds, organizationIds } = computeSubjectRestrictions(subjects, settingsEntity?.platform_organization);
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
  return { proposal: created, created: true, suppressed: false };
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
