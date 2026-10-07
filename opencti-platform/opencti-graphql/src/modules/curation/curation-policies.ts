import * as R from 'ramda';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreBase, BasicStoreEntity } from '../../types/store';
import { FunctionalError } from '../../config/errors';
import { checkEnterpriseEdition } from '../../enterprise-edition/ee';
import { createInternalObject, deleteInternalObject, editInternalObject } from '../../domain/internalObject';
import { fullEntitiesList, internalFindByIds, pageEntitiesConnection, storeLoadById, type EntityOptions } from '../../database/middleware-loader';
import { patchAttribute } from '../../database/middleware';
import { elCount } from '../../database/engine';
import { READ_INDEX_INTERNAL_OBJECTS } from '../../database/utils';
import { getEntitiesListFromCache } from '../../database/cache';
import { ENTITY_TYPE_BACKGROUND_TASK, ENTITY_TYPE_CONNECTOR } from '../../schema/internalObject';
import { RELATION_GRANTED_TO, RELATION_OBJECT_MARKING } from '../../schema/stixRefRelationship';
import { SYSTEM_USER } from '../../utils/access';
import { createListTask } from '../../domain/backgroundTask-common';
import { ACTION_TYPE_CURATION_APPLY, TASK_TYPE_LIST } from '../../domain/backgroundTask-common';
import { withPolicySchedulingLock } from './curation-locks';
import { EditOperation, FilterMode, FilterOperator, type EditInput } from '../../generated/graphql';
import { now } from '../../utils/format';
import {
  ACTION_UNMERGE,
  type BasicStoreEntityCurationPolicy,
  type BasicStoreEntityCurationProposal,
  type CurationPolicyDryRunResult,
  DECISION_ALIAS,
  DECISION_MERGE,
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
  PROPOSAL_STATUS_AUTO_APPLIED,
  PROPOSAL_STATUS_OPEN,
  PROPOSAL_STATUS_REVERTED,
  type PolicySourceClass,
  type ProposalKind,
  SOURCE_CLASS_ANY,
  SOURCE_CLASS_CONNECTOR,
  SOURCE_CLASS_MANUAL,
} from './curation-types';
import { isCuratableEntityType } from './curation-settings';
import { ADJUDICATED_PROPOSAL_KINDS } from './curation-adjudication';
import { canUserApplyProposal, isProposalChoiceRequired } from './curation-access';

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
const DRY_RUN_SAMPLE_SIZE = 10;
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
export const EXCLUSION_MISSING_CAPABILITY = 'missing_capability';

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
 * Guardrails that no policy can disable: never apply a proposal whose subjects have different markings or
 * organizations, never apply a choice that needs a human (attribution conflicts, splits).
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
  if (isProposalChoiceRequired(proposal) || proposal.recommended_action === ACTION_UNMERGE) return EXCLUSION_MANUAL_CHOICE;
  if (!facts.subjectsFound) return EXCLUSION_SUBJECT_MISSING;
  if (proposal.confidence_score < policy.auto_apply_threshold) return EXCLUSION_THRESHOLD;
  if (policy.policy_source_class !== SOURCE_CLASS_ANY && facts.sourceClass !== policy.policy_source_class) return EXCLUSION_SOURCE_CLASS;
  // Every kind: an alias addition copies a name from one subject to another, which must not cross restrictions either.
  if (!sameSets(facts.markingSets)) return EXCLUSION_CROSS_MARKINGS;
  if (!sameSets(facts.organizationSets)) return EXCLUSION_CROSS_ORGANIZATIONS;
  if (policy.forbid_open_contradiction && hasOpenContradiction) return EXCLUSION_OPEN_CONTRADICTION;
  // Only an adjudication OpenCTI obtained from the bound agent counts: a decision recorded through the API does not.
  const adjudication = proposal.curation_adjudication?.verified === true ? proposal.curation_adjudication : null;
  // An alias decision on a merge proposal keeps apart entities whose names cannot become aliases while they exist (an
  // alias names a single entity): merging them or keeping them apart is a human choice.
  if (proposal.proposal_kind === PROPOSAL_KIND_MERGE && adjudication?.decision === DECISION_ALIAS) return EXCLUSION_MANUAL_CHOICE;
  // A merge decision on an alias proposal asks for a merge, which a policy never runs in place of the aliases it applies.
  if (proposal.proposal_kind === PROPOSAL_KIND_ALIAS && adjudication?.decision === DECISION_MERGE) return EXCLUSION_MANUAL_CHOICE;
  // Agreement can only be required where the Curator adjudicates: the other kinds are never sent to it.
  if (policy.require_adjudication && ADJUDICATED_PROPOSAL_KINDS.includes(proposal.proposal_kind)) {
    const decision = adjudication?.decision;
    if (!decision || decision === DECISION_SKIP) return EXCLUSION_ADJUDICATION_MISSING;
    const agrees = decision === (proposal.proposal_kind === PROPOSAL_KIND_MERGE ? DECISION_MERGE : DECISION_ALIAS);
    if (!agrees) return EXCLUSION_ADJUDICATION_DISAGREES;
  }
  return null;
};

// region facts loading
const loadConnectorUserIds = async (context: AuthContext) => {
  const connectors = await getEntitiesListFromCache<BasicStoreEntity & { connector_user_id?: string }>(context, SYSTEM_USER, ENTITY_TYPE_CONNECTOR);
  return new Set(connectors.map((connector) => connector.connector_user_id).filter((id): id is string => !!id));
};

// A subject comes from the source that created it, its first creator: the writers that updated it since do not count.
export const computeSourceClass = (creatorIds: string[][], connectorUserIds: Set<string>): PolicySourceClass | 'mixed' => {
  const classes = creatorIds.map(([creatorId]) => (creatorId && connectorUserIds.has(creatorId) ? SOURCE_CLASS_CONNECTOR : SOURCE_CLASS_MANUAL));
  const unique = R.uniq(classes);
  return unique.length === 1 ? unique[0] as PolicySourceClass | 'mixed' : 'mixed';
};

export const loadPolicyFacts = async (context: AuthContext, proposals: BasicStoreEntityCurationProposal[]) => {
  const subjectIds = R.uniq(proposals.flatMap((proposal) => proposal.subject_ids));
  const subjects = subjectIds.length > 0
    ? await internalFindByIds(context, SYSTEM_USER, subjectIds, { toMap: true, baseData: true }) as unknown as Record<string, BasicStoreBase & Record<string, any>>
    : {};
  // Only the open contradictions about these subjects matter: a policy apply re-checks one proposal at a time.
  const contradictions = subjectIds.length > 0
    ? await fullEntitiesList<BasicStoreEntityCurationProposal>(context, SYSTEM_USER, [ENTITY_TYPE_CURATION_PROPOSAL], {
        filters: {
          mode: FilterMode.And,
          filters: [
            { key: ['proposal_kind'], values: [PROPOSAL_KIND_CONTRADICTION], operator: FilterOperator.Eq },
            { key: ['proposal_status'], values: [PROPOSAL_STATUS_OPEN], operator: FilterOperator.Eq },
            { key: ['subject_ids'], values: subjectIds, operator: FilterOperator.Eq },
          ],
          filterGroups: [],
        },
        noFiltersChecking: true,
      })
    : [];
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
  // An edit goes through the generic edit input, which does not carry the constraints of the creation input.
  if (input.name !== undefined && (typeof input.name !== 'string' || input.name.trim().length < 2)) {
    throw FunctionalError('The policy name needs at least 2 characters', { name: input.name });
  }
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
  };
  validatePolicyInput(finalInput);
  return createInternalObject<any>(context, user, finalInput, ENTITY_TYPE_CURATION_POLICY);
};

const EDITABLE_POLICY_KEYS = ['name', 'description', 'policy_enabled', 'policy_entity_types', 'policy_kinds', 'policy_source_class', 'auto_apply_threshold',
  'forbid_open_contradiction', 'require_adjudication', 'max_applies_per_run'];
const MULTIPLE_POLICY_KEYS = ['policy_entity_types', 'policy_kinds'];
// Every editable field but the description: an edit may change them, never empty them.
const REQUIRED_POLICY_KEYS = EDITABLE_POLICY_KEYS.filter((key) => key !== 'description' && key !== 'policy_entity_types');

/** The policy an edit produces: its operations applied to the stored policy, as the platform will store it. */
export const applyPolicyEdits = (policy: Record<string, any>, input: EditInput[]): Record<string, any> => {
  const next: Record<string, any> = { ...policy };
  input.forEach((edit) => {
    const values = (edit.value ?? []) as unknown[];
    if (MULTIPLE_POLICY_KEYS.includes(edit.key)) {
      const current = (next[edit.key] ?? []) as unknown[];
      if (edit.operation === EditOperation.Add) next[edit.key] = R.uniq([...current, ...values]);
      else if (edit.operation === EditOperation.Remove) next[edit.key] = current.filter((value) => !values.includes(value));
      else next[edit.key] = values;
    } else {
      next[edit.key] = edit.operation === EditOperation.Remove ? undefined : values[0];
    }
  });
  return next;
};

export const editCurationPolicy = async (context: AuthContext, user: AuthUser, id: string, input: EditInput[]) => {
  await checkEnterpriseEdition(context);
  if (input.some((edit) => !EDITABLE_POLICY_KEYS.includes(edit.key))) {
    throw FunctionalError('Invalid or forbidden key for a curation policy', { keys: input.map((edit) => edit.key) });
  }
  const policy = await findPolicyById(context, user, id);
  if (!policy) {
    throw FunctionalError('Curation policy not found', { id });
  }
  // The resulting policy is validated, not the edit: removing the last kind or a required value is refused.
  const next = applyPolicyEdits(policy, input);
  const emptied = REQUIRED_POLICY_KEYS.filter((key) => next[key] === undefined || next[key] === null || next[key] === '');
  if (emptied.length > 0) {
    throw FunctionalError('These curation policy fields cannot be emptied', { keys: emptied });
  }
  validatePolicyInput(R.pick(EDITABLE_POLICY_KEYS, next));
  return editInternalObject<any>(context, user, id, ENTITY_TYPE_CURATION_POLICY, input);
};

export const deleteCurationPolicy = async (context: AuthContext, user: AuthUser, id: string) => {
  await checkEnterpriseEdition(context);
  return deleteInternalObject(context, user, id, ENTITY_TYPE_CURATION_POLICY);
};
// endregion

// region dry run and apply
// A run only reads the proposals it may apply (covered kinds at or above the threshold); a dry run reads every open
// proposal of the covered kinds, so that the ones below the threshold are counted as excluded.
const candidateFilters = (policy: BasicStoreEntityCurationPolicy, opts: { anyConfidence: boolean }) => {
  const filters = [
    { key: ['proposal_status'], values: [PROPOSAL_STATUS_OPEN], operator: FilterOperator.Eq },
    { key: ['proposal_kind'], values: policy.policy_kinds, operator: FilterOperator.Eq },
  ];
  if (!opts.anyConfidence) {
    filters.push({ key: ['confidence_score'], values: [String(policy.auto_apply_threshold)], operator: FilterOperator.Gte });
  }
  return { mode: FilterMode.And, filters, filterGroups: [] };
};

/**
 * The proposals a policy applied, counted from the proposals themselves: only a policy application records its policy,
 * and a revert keeps it, so a task retried after a failure can neither miss an application nor count it twice.
 */
export const countPolicyApplications = async (context: AuthContext, policy: BasicStoreEntityCurationPolicy) => {
  return elCount(context, SYSTEM_USER, READ_INDEX_INTERNAL_OBJECTS, {
    types: [ENTITY_TYPE_CURATION_PROPOSAL],
    filters: {
      mode: FilterMode.And,
      filters: [
        { key: ['policy_id'], values: [policy.internal_id], operator: FilterOperator.Eq },
        { key: ['proposal_status'], values: [PROPOSAL_STATUS_AUTO_APPLIED, PROPOSAL_STATUS_REVERTED], operator: FilterOperator.Eq, mode: FilterMode.Or },
      ],
      filterGroups: [],
    },
  });
};

// The open proposals of the kinds a policy does not cover: excluded by their kind, before anything else is checked.
const countUncoveredProposals = async (context: AuthContext, user: AuthUser, policy: BasicStoreEntityCurationPolicy) => {
  return elCount(context, user, READ_INDEX_INTERNAL_OBJECTS, {
    types: [ENTITY_TYPE_CURATION_PROPOSAL],
    filters: {
      mode: FilterMode.And,
      filters: [
        { key: ['proposal_status'], values: [PROPOSAL_STATUS_OPEN], operator: FilterOperator.Eq },
        { key: ['proposal_kind'], values: policy.policy_kinds, operator: FilterOperator.NotEq, mode: FilterMode.And },
      ],
      filterGroups: [],
    },
  });
};

/**
 * The proposals a policy run applies: the covered kinds at or above the threshold, highest confidence first, read page by
 * page until *limit* eligible ones no apply task holds are found or every candidate was read, so the proposals the
 * policy excludes never hold back the eligible ones below them.
 */
export const findApplicableProposals = async (
  context: AuthContext,
  user: AuthUser,
  policy: BasicStoreEntityCurationPolicy,
  opts: { limit: number; skip: Set<string> },
) => {
  const applicable: BasicStoreEntityCurationProposal[] = [];
  if (opts.limit <= 0) return applicable;
  // The proposals are applied with the rights of the user running the policy: the ones this user could not read or
  // accept directly are left to a scheduled run or an analyst.
  await fullEntitiesList<BasicStoreEntityCurationProposal>(context, user, [ENTITY_TYPE_CURATION_PROPOSAL], {
    filters: candidateFilters(policy, { anyConfidence: false }),
    orderBy: 'confidence_score',
    orderMode: 'desc' as any,
    callback: async (proposals: BasicStoreEntityCurationProposal[]) => {
      const pending = proposals.filter((proposal) => !opts.skip.has(proposal.internal_id) && canUserApplyProposal(user, proposal));
      const { factsFor, hasOpenContradiction } = await loadPolicyFacts(context, pending);
      for (let index = 0; index < pending.length; index += 1) {
        const proposal = pending[index];
        if (!evaluatePolicyEligibility(policy, proposal, factsFor(proposal), hasOpenContradiction(proposal))) {
          applicable.push(proposal);
          if (applicable.length >= opts.limit) return false;
        }
      }
      return true;
    },
  } as any);
  return applicable;
};

/**
 * A dry run evaluates every open proposal the requesting user can read, as a manual run of the policy reads them: the
 * covered kinds at any confidence, page by page with only the counts kept, so its totals hold however many proposals
 * there are, and the other kinds, counted as not covered. An eligible proposal whose action needs a capability the user
 * lacks is excluded, as a manual run leaves it out (a scheduled run, with the rights of the curation manager, applies it).
 */
export const evaluateDryRun = async (context: AuthContext, user: AuthUser, policy: BasicStoreEntityCurationPolicy) => {
  let eligibleCount = 0;
  const exclusions: Record<string, number> = {};
  const impact: Record<string, number> = {};
  const sampleIds: string[] = [];
  await fullEntitiesList<BasicStoreEntityCurationProposal>(context, user, [ENTITY_TYPE_CURATION_PROPOSAL], {
    filters: candidateFilters(policy, { anyConfidence: true }),
    orderBy: 'confidence_score',
    orderMode: 'desc' as any,
    callback: async (proposals: BasicStoreEntityCurationProposal[]) => {
      const { factsFor, hasOpenContradiction } = await loadPolicyFacts(context, proposals);
      proposals.forEach((proposal) => {
        const reason = evaluatePolicyEligibility(policy, proposal, factsFor(proposal), hasOpenContradiction(proposal))
          ?? (canUserApplyProposal(user, proposal) ? null : EXCLUSION_MISSING_CAPABILITY);
        if (reason) {
          exclusions[reason] = (exclusions[reason] ?? 0) + 1;
          return;
        }
        eligibleCount += 1;
        const key = `${proposal.proposal_kind}:${R.uniq(proposal.subject_types).join('+')}`;
        impact[key] = (impact[key] ?? 0) + 1;
        if (sampleIds.length < DRY_RUN_SAMPLE_SIZE) sampleIds.push(proposal.internal_id);
      });
    },
  } as any);
  const uncovered = await countUncoveredProposals(context, user, policy);
  if (uncovered > 0) exclusions[EXCLUSION_KIND] = (exclusions[EXCLUSION_KIND] ?? 0) + uncovered;
  return { eligibleCount, exclusions, impact, sampleIds };
};

export const dryRunCurationPolicy = async (context: AuthContext, user: AuthUser, id: string): Promise<CurationPolicyDryRunResult> => {
  await checkEnterpriseEdition(context);
  const policy = await findPolicyById(context, user, id);
  if (!policy) throw FunctionalError('Curation policy not found', { id });
  const { eligibleCount, exclusions, impact, sampleIds } = await evaluateDryRun(context, user, policy);
  const result: CurationPolicyDryRunResult = {
    computed_at: now(),
    eligible_count: eligibleCount,
    excluded_count: Object.values(exclusions).reduce((acc, count) => acc + count, 0),
    estimated_impact: Object.entries(impact).map(([key, count]) => ({ key, count })).sort((a, b) => b.count - a.count),
    exclusions: Object.entries(exclusions).map(([key, count]) => ({ key, count })).sort((a, b) => b.count - a.count),
    sample_proposal_ids: sampleIds,
    computed_by_id: user.id,
  };
  await patchAttribute(context, SYSTEM_USER, policy.internal_id, ENTITY_TYPE_CURATION_POLICY, { last_dry_run: result });
  return result;
};

type CurationApplyTask = BasicStoreEntity & { actions?: Array<{ type: string }>; task_ids?: string[] };

/**
 * The proposals a queued or running apply task already holds (a policy run or a bulk acceptance). A worker backlog
 * longer than the policy interval never queues them a second time: the transition lock only keeps the graph from
 * changing twice, not the task and its work from being created again.
 */
export const findQueuedProposalIds = async (context: AuthContext) => {
  const tasks = await fullEntitiesList<CurationApplyTask>(context, SYSTEM_USER, [ENTITY_TYPE_BACKGROUND_TASK], {
    filters: {
      mode: FilterMode.And,
      filters: [{ key: ['completed'], values: ['false'] }, { key: ['type'], values: [TASK_TYPE_LIST] }],
      filterGroups: [],
    },
    noFiltersChecking: true,
  } as EntityOptions<CurationApplyTask>);
  return new Set(tasks
    .filter((task) => (task.actions ?? []).some((action) => action.type === ACTION_TYPE_CURATION_APPLY))
    .flatMap((task) => task.task_ids ?? []));
};

/**
 * Apply a policy now: the eligible proposals (bounded by max_applies_per_run) that no apply task holds yet are applied
 * by a background task run by the distributed workers, with the rights of the initiator, and re-checked one by one at
 * apply time.
 */
export const applyCurationPolicy = async (context: AuthContext, user: AuthUser, policy: BasicStoreEntityCurationPolicy): Promise<string | null> => {
  await checkEnterpriseEdition(context);
  return withPolicySchedulingLock(async () => {
    const queued = await findQueuedProposalIds(context);
    const toApply = await findApplicableProposals(context, user, policy, { limit: policy.max_applies_per_run, skip: queued });
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
    return task.id as string;
  });
};

/** Apply now, refused for a disabled policy: the workers skip every proposal of a policy that is not enabled. */
export const applyCurationPolicyById = async (context: AuthContext, user: AuthUser, id: string) => {
  const policy = await findPolicyById(context, user, id);
  if (!policy) throw FunctionalError('Curation policy not found', { id });
  if (!policy.policy_enabled) throw FunctionalError('Enable the curation policy to apply it now', { id });
  return applyCurationPolicy(context, user, policy);
};
// endregion
