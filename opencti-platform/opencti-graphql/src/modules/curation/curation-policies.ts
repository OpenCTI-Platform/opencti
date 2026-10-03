import * as R from 'ramda';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreBase, BasicStoreEntity } from '../../types/store';
import { FunctionalError } from '../../config/errors';
import { checkEnterpriseEdition } from '../../enterprise-edition/ee';
import { createInternalObject, deleteInternalObject, editInternalObject } from '../../domain/internalObject';
import { fullEntitiesList, internalFindByIds, pageEntitiesConnection, storeLoadById, type EntityOptions } from '../../database/middleware-loader';
import { patchAttribute } from '../../database/middleware';
import { getEntitiesListFromCache } from '../../database/cache';
import { ENTITY_TYPE_CONNECTOR } from '../../schema/internalObject';
import { RELATION_GRANTED_TO, RELATION_OBJECT_MARKING } from '../../schema/stixRefRelationship';
import { SYSTEM_USER } from '../../utils/access';
import { createListTask } from '../../domain/backgroundTask-common';
import { ACTION_TYPE_CURATION_APPLY } from '../../domain/backgroundTask-common';
import { FilterMode, FilterOperator, type EditInput } from '../../generated/graphql';
import { now } from '../../utils/format';
import {
  ACTION_MERGE,
  type BasicStoreEntityCurationPolicy,
  type BasicStoreEntityCurationProposal,
  type CurationPolicyDryRunResult,
  DECISION_ALIAS,
  DECISION_MERGE,
  DECISION_DISTINCT,
  DECISION_SKIP,
  ENTITY_TYPE_CURATION_POLICY,
  ENTITY_TYPE_CURATION_PROPOSAL,
  POLICY_SOURCE_CLASSES,
  PROPOSAL_KIND_ALIAS,
  PROPOSAL_KIND_CONTRADICTION,
  PROPOSAL_KIND_FIELD_PRECEDENCE,
  PROPOSAL_KIND_MERGE,
  PROPOSAL_KIND_RELATIONSHIP_CONFLICT,
  PROPOSAL_KIND_STALE,
  PROPOSAL_KIND_TYPE_MISMATCH,
  PROPOSAL_STATUS_OPEN,
  type PolicySourceClass,
  type ProposalKind,
  SOURCE_CLASS_ANY,
  SOURCE_CLASS_CONNECTOR,
  SOURCE_CLASS_MANUAL,
} from './curation-types';
import { isCuratableEntityType } from './curation-settings';
import { ADJUDICATED_PROPOSAL_KINDS } from './curation-adjudication';

// Split proposals (unmerge) always need a human decision.
export const AUTO_APPLICABLE_KINDS: ProposalKind[] = [
  PROPOSAL_KIND_MERGE,
  PROPOSAL_KIND_ALIAS,
  PROPOSAL_KIND_CONTRADICTION,
  PROPOSAL_KIND_STALE,
  PROPOSAL_KIND_TYPE_MISMATCH,
  PROPOSAL_KIND_RELATIONSHIP_CONFLICT,
  PROPOSAL_KIND_FIELD_PRECEDENCE,
];
const MIN_AUTO_APPLY_THRESHOLD = 0.5;
const DRY_RUN_MAX_PROPOSALS = 10000;
const MAX_APPLIES_PER_RUN = 1000;

export const EXCLUSION_NOT_OPEN = 'not_open';
export const EXCLUSION_KIND = 'kind_not_covered';
export const EXCLUSION_ENTITY_TYPE = 'entity_type_not_covered';
export const EXCLUSION_THRESHOLD = 'below_threshold';
export const EXCLUSION_SOURCE_CLASS = 'source_class_mismatch';
export const EXCLUSION_CROSS_MARKINGS = 'cross_markings';
export const EXCLUSION_CROSS_ORGANIZATIONS = 'cross_organizations';
export const EXCLUSION_OPEN_CONTRADICTION = 'open_contradiction';
export const EXCLUSION_ADJUDICATION_MISSING = 'adjudication_missing';
export const EXCLUSION_ADJUDICATION_DISAGREES = 'adjudication_disagrees';
export const EXCLUSION_MANUAL_CHOICE = 'manual_choice_required';
export const EXCLUSION_SUBJECT_MISSING = 'subject_missing';

export interface PolicySubjectFacts {
  markingSets: string[][];
  organizationSets: string[][];
  sourceClass: PolicySourceClass | 'mixed';
  subjectsFound: boolean;
}

const sameSets = (sets: string[][]) => {
  if (sets.length < 2) return true;
  const reference = [...sets[0]].sort().join(',');
  return sets.every((set) => [...set].sort().join(',') === reference);
};

/**
 * Decide whether a policy may apply a proposal on its own. Returns the exclusion reason, or null when eligible.
 * Guardrails that no policy can disable: never merge across different markings or organizations, never apply a
 * choice that needs a human (attribution conflicts, splits).
 */
export const evaluatePolicyEligibility = (
  policy: Pick<BasicStoreEntityCurationPolicy, 'policy_kinds' | 'policy_entity_types' | 'auto_apply_threshold' | 'policy_source_class' | 'forbid_open_contradiction' | 'require_adjudication'>,
  proposal: Pick<BasicStoreEntityCurationProposal, 'proposal_status' | 'proposal_kind' | 'subject_types' | 'confidence_score' | 'recommended_action' | 'curation_adjudication' | 'subject_ids'>,
  facts: PolicySubjectFacts,
  hasOpenContradiction: boolean,
): string | null => {
  if (proposal.proposal_status !== PROPOSAL_STATUS_OPEN) return EXCLUSION_NOT_OPEN;
  if (!policy.policy_kinds.includes(proposal.proposal_kind) || !AUTO_APPLICABLE_KINDS.includes(proposal.proposal_kind)) return EXCLUSION_KIND;
  if (policy.policy_entity_types.length > 0 && !proposal.subject_types.every((type) => policy.policy_entity_types.includes(type))) return EXCLUSION_ENTITY_TYPE;
  if (proposal.recommended_action === 'resolve_attribution' || proposal.recommended_action === 'unmerge') return EXCLUSION_MANUAL_CHOICE;
  if (!facts.subjectsFound) return EXCLUSION_SUBJECT_MISSING;
  if (proposal.confidence_score < policy.auto_apply_threshold) return EXCLUSION_THRESHOLD;
  if (policy.policy_source_class !== SOURCE_CLASS_ANY && facts.sourceClass !== policy.policy_source_class) return EXCLUSION_SOURCE_CLASS;
  if (proposal.recommended_action === ACTION_MERGE || proposal.proposal_kind === PROPOSAL_KIND_MERGE) {
    if (!sameSets(facts.markingSets)) return EXCLUSION_CROSS_MARKINGS;
    if (!sameSets(facts.organizationSets)) return EXCLUSION_CROSS_ORGANIZATIONS;
  }
  if (policy.forbid_open_contradiction && hasOpenContradiction) return EXCLUSION_OPEN_CONTRADICTION;
  // Agreement can only be required where the Curator adjudicates: the other kinds are never sent to it.
  if (policy.require_adjudication && ADJUDICATED_PROPOSAL_KINDS.includes(proposal.proposal_kind)) {
    const decision = proposal.curation_adjudication?.decision;
    if (!decision || decision === DECISION_SKIP) return EXCLUSION_ADJUDICATION_MISSING;
    const agrees = proposal.proposal_kind === PROPOSAL_KIND_MERGE ? (decision === DECISION_MERGE || decision === DECISION_ALIAS) : decision !== DECISION_DISTINCT;
    if (!agrees) return EXCLUSION_ADJUDICATION_DISAGREES;
  }
  return null;
};

// region facts loading
const loadConnectorUserIds = async (context: AuthContext) => {
  const connectors = await getEntitiesListFromCache<BasicStoreEntity & { connector_user_id?: string }>(context, SYSTEM_USER, ENTITY_TYPE_CONNECTOR);
  return new Set(connectors.map((connector) => connector.connector_user_id).filter((id): id is string => !!id));
};

export const computeSourceClass = (creatorIds: string[][], connectorUserIds: Set<string>): PolicySourceClass | 'mixed' => {
  const classes = creatorIds.map((ids) => {
    if (ids.length === 0) return SOURCE_CLASS_MANUAL;
    const fromConnector = ids.every((id) => connectorUserIds.has(id));
    const fromHumans = ids.every((id) => !connectorUserIds.has(id));
    if (fromConnector) return SOURCE_CLASS_CONNECTOR;
    if (fromHumans) return SOURCE_CLASS_MANUAL;
    return 'mixed';
  });
  const unique = R.uniq(classes);
  return unique.length === 1 ? unique[0] as PolicySourceClass | 'mixed' : 'mixed';
};

export const loadPolicyFacts = async (context: AuthContext, proposals: BasicStoreEntityCurationProposal[]) => {
  const subjectIds = R.uniq(proposals.flatMap((proposal) => proposal.subject_ids));
  const subjects = subjectIds.length > 0
    ? await internalFindByIds(context, SYSTEM_USER, subjectIds, { toMap: true, baseData: true }) as unknown as Record<string, BasicStoreBase & Record<string, any>>
    : {};
  const contradictions = await fullEntitiesList<BasicStoreEntityCurationProposal>(context, SYSTEM_USER, [ENTITY_TYPE_CURATION_PROPOSAL], {
    filters: {
      mode: FilterMode.And,
      filters: [
        { key: ['proposal_kind'], values: [PROPOSAL_KIND_CONTRADICTION], operator: FilterOperator.Eq },
        { key: ['proposal_status'], values: [PROPOSAL_STATUS_OPEN], operator: FilterOperator.Eq },
      ],
      filterGroups: [],
    },
    noFiltersChecking: true,
  });
  const contradictedIds = new Set(contradictions.flatMap((proposal) => proposal.subject_ids));
  const connectorUserIds = await loadConnectorUserIds(context);
  const factsFor = (proposal: BasicStoreEntityCurationProposal): PolicySubjectFacts => {
    const loaded = proposal.subject_ids.map((id) => subjects[id]).filter(Boolean);
    const creators = loaded.map((subject) => {
      const creatorId = subject.creator_id;
      return (Array.isArray(creatorId) ? creatorId : [creatorId]).filter(Boolean) as string[];
    });
    return {
      markingSets: loaded.map((subject) => (subject[RELATION_OBJECT_MARKING] ?? []) as string[]),
      organizationSets: loaded.map((subject) => (subject[RELATION_GRANTED_TO] ?? []) as string[]),
      sourceClass: computeSourceClass(creators, connectorUserIds),
      subjectsFound: loaded.length === proposal.subject_ids.length,
    };
  };
  const hasOpenContradiction = (proposal: BasicStoreEntityCurationProposal) => proposal.proposal_kind !== PROPOSAL_KIND_CONTRADICTION
    && proposal.subject_ids.some((id) => contradictedIds.has(id));
  return { factsFor, hasOpenContradiction };
};
// endregion

// region CRUD
const validatePolicyInput = (input: Record<string, any>) => {
  if (input.auto_apply_threshold !== undefined) {
    const threshold = Number(input.auto_apply_threshold);
    if (!Number.isFinite(threshold) || threshold < MIN_AUTO_APPLY_THRESHOLD || threshold > 1) {
      throw FunctionalError('The auto-apply threshold must be between 0.5 and 1', { auto_apply_threshold: input.auto_apply_threshold });
    }
  }
  if (input.policy_kinds !== undefined) {
    const kinds = input.policy_kinds as string[];
    if (kinds.length === 0 || kinds.some((kind) => !AUTO_APPLICABLE_KINDS.includes(kind as ProposalKind))) {
      throw FunctionalError('A policy needs at least one auto-applicable proposal kind (split proposals always need a human)', { policy_kinds: kinds });
    }
  }
  if (input.policy_entity_types !== undefined && (input.policy_entity_types as string[]).some((type) => !isCuratableEntityType(type))) {
    throw FunctionalError('Policies only apply to knowledge entity types', { policy_entity_types: input.policy_entity_types });
  }
  if (input.policy_source_class !== undefined && !(POLICY_SOURCE_CLASSES as readonly string[]).includes(input.policy_source_class)) {
    throw FunctionalError('Unknown source class', { policy_source_class: input.policy_source_class });
  }
  if (input.max_applies_per_run !== undefined) {
    const max = Number(input.max_applies_per_run);
    if (!Number.isInteger(max) || max < 1 || max > MAX_APPLIES_PER_RUN) {
      throw FunctionalError('The maximum applies per run must be between 1 and 1000', { max_applies_per_run: input.max_applies_per_run });
    }
  }
};

export const findPolicyById = async (context: AuthContext, user: AuthUser, id: string) => {
  return storeLoadById<BasicStoreEntityCurationPolicy>(context, user, id, ENTITY_TYPE_CURATION_POLICY);
};

export const findPoliciesPaginated = async (context: AuthContext, user: AuthUser, opts: EntityOptions<BasicStoreEntityCurationPolicy>) => {
  return pageEntitiesConnection<BasicStoreEntityCurationPolicy>(context, user, [ENTITY_TYPE_CURATION_POLICY], opts);
};

export const findEnabledPolicies = async (context: AuthContext) => {
  return fullEntitiesList<BasicStoreEntityCurationPolicy>(context, SYSTEM_USER, [ENTITY_TYPE_CURATION_POLICY], {
    filters: { mode: FilterMode.And, filters: [{ key: ['policy_enabled'], values: ['true'], operator: FilterOperator.Eq }], filterGroups: [] },
  });
};

export const addCurationPolicy = async (context: AuthContext, user: AuthUser, input: Record<string, any>) => {
  await checkEnterpriseEdition(context);
  const finalInput = {
    name: input.name,
    description: input.description ?? null,
    policy_enabled: input.policy_enabled ?? false,
    policy_entity_types: input.policy_entity_types ?? [],
    policy_kinds: input.policy_kinds,
    policy_source_class: input.policy_source_class ?? SOURCE_CLASS_ANY,
    auto_apply_threshold: input.auto_apply_threshold,
    forbid_open_contradiction: input.forbid_open_contradiction ?? true,
    require_adjudication: input.require_adjudication ?? false,
    max_applies_per_run: input.max_applies_per_run ?? 100,
    applied_count: 0,
  };
  validatePolicyInput(finalInput);
  return createInternalObject<any>(context, user, finalInput, ENTITY_TYPE_CURATION_POLICY);
};

const EDITABLE_POLICY_KEYS = ['name', 'description', 'policy_enabled', 'policy_entity_types', 'policy_kinds', 'policy_source_class', 'auto_apply_threshold',
  'forbid_open_contradiction', 'require_adjudication', 'max_applies_per_run'];

export const editCurationPolicy = async (context: AuthContext, user: AuthUser, id: string, input: EditInput[]) => {
  await checkEnterpriseEdition(context);
  if (input.some((edit) => !EDITABLE_POLICY_KEYS.includes(edit.key))) {
    throw FunctionalError('Invalid or forbidden key for a curation policy', { keys: input.map((edit) => edit.key) });
  }
  const asObject: Record<string, any> = {};
  input.forEach((edit) => {
    const multiple = ['policy_entity_types', 'policy_kinds'].includes(edit.key);
    asObject[edit.key] = multiple ? edit.value : edit.value?.[0];
  });
  validatePolicyInput(asObject);
  return editInternalObject<any>(context, user, id, ENTITY_TYPE_CURATION_POLICY, input);
};

export const deleteCurationPolicy = async (context: AuthContext, user: AuthUser, id: string) => {
  await checkEnterpriseEdition(context);
  return deleteInternalObject(context, user, id, ENTITY_TYPE_CURATION_POLICY);
};
// endregion

// region dry run and apply
const loadCandidateProposals = async (context: AuthContext, policy: BasicStoreEntityCurationPolicy) => {
  const filters = [
    { key: ['proposal_status'], values: [PROPOSAL_STATUS_OPEN], operator: FilterOperator.Eq },
    { key: ['proposal_kind'], values: policy.policy_kinds, operator: FilterOperator.Eq },
    { key: ['confidence_score'], values: [String(policy.auto_apply_threshold)], operator: FilterOperator.Gte },
  ];
  return fullEntitiesList<BasicStoreEntityCurationProposal>(context, SYSTEM_USER, [ENTITY_TYPE_CURATION_PROPOSAL], {
    filters: { mode: FilterMode.And, filters, filterGroups: [] },
    orderBy: 'confidence_score',
    orderMode: 'desc' as any,
    maxSize: DRY_RUN_MAX_PROPOSALS,
  } as any);
};

export const computePolicyEvaluation = async (context: AuthContext, policy: BasicStoreEntityCurationPolicy) => {
  const proposals = await loadCandidateProposals(context, policy);
  const { factsFor, hasOpenContradiction } = await loadPolicyFacts(context, proposals);
  const eligible: BasicStoreEntityCurationProposal[] = [];
  const exclusions: Record<string, number> = {};
  proposals.forEach((proposal) => {
    const reason = evaluatePolicyEligibility(policy, proposal, factsFor(proposal), hasOpenContradiction(proposal));
    if (reason) {
      exclusions[reason] = (exclusions[reason] ?? 0) + 1;
    } else {
      eligible.push(proposal);
    }
  });
  return { eligible, exclusions };
};

export const dryRunCurationPolicy = async (context: AuthContext, user: AuthUser, id: string): Promise<CurationPolicyDryRunResult> => {
  await checkEnterpriseEdition(context);
  const policy = await findPolicyById(context, user, id);
  if (!policy) throw FunctionalError('Curation policy not found', { id });
  const { eligible, exclusions } = await computePolicyEvaluation(context, policy);
  const impact: Record<string, number> = {};
  eligible.forEach((proposal) => {
    const key = `${proposal.proposal_kind}:${R.uniq(proposal.subject_types).join('+')}`;
    impact[key] = (impact[key] ?? 0) + 1;
  });
  const result: CurationPolicyDryRunResult = {
    computed_at: now(),
    eligible_count: eligible.length,
    excluded_count: Object.values(exclusions).reduce((acc, count) => acc + count, 0),
    estimated_impact: Object.entries(impact).map(([key, count]) => ({ key, count })).sort((a, b) => b.count - a.count),
    exclusions: Object.entries(exclusions).map(([key, count]) => ({ key, count })).sort((a, b) => b.count - a.count),
    sample_proposal_ids: eligible.slice(0, 10).map((proposal) => proposal.internal_id),
  };
  await patchAttribute(context, SYSTEM_USER, policy.internal_id, ENTITY_TYPE_CURATION_POLICY, { last_dry_run: result });
  return result;
};

/**
 * Apply a policy now: the eligible proposals (bounded by max_applies_per_run) are applied by a background task run by
 * the distributed workers, with the rights of the initiator, and re-checked one by one at apply time.
 */
export const applyCurationPolicy = async (context: AuthContext, user: AuthUser, policy: BasicStoreEntityCurationPolicy): Promise<string | null> => {
  await checkEnterpriseEdition(context);
  const { eligible } = await computePolicyEvaluation(context, policy);
  const toApply = eligible.slice(0, policy.max_applies_per_run);
  if (toApply.length === 0) {
    return null;
  }
  const task = await createListTask(context, user, {
    ids: toApply.map((proposal) => proposal.internal_id),
    scope: 'KNOWLEDGE',
    actions: [{ type: ACTION_TYPE_CURATION_APPLY, context: { values: [policy.internal_id] } }],
    description: `Curation policy ${policy.name}: apply ${toApply.length} proposal(s)`,
  });
  await patchAttribute(context, SYSTEM_USER, policy.internal_id, ENTITY_TYPE_CURATION_POLICY, { last_applied_at: now() });
  return task.id;
};

export const applyCurationPolicyById = async (context: AuthContext, user: AuthUser, id: string) => {
  const policy = await findPolicyById(context, user, id);
  if (!policy) throw FunctionalError('Curation policy not found', { id });
  return applyCurationPolicy(context, user, policy);
};
// endregion
