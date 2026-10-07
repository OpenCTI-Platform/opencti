import { findByIds } from './hunt-loaders';
import type { FileHandle } from 'fs/promises';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreEntity, BasicStoreObject } from '../../types/store';
import { BUS_TOPICS, logApp } from '../../config/conf';
import { FunctionalError, ResourceNotFoundError, UnsupportedError, ValidationError } from '../../config/errors';
import { createEntity, deleteElementById } from '../../database/middleware';
import {
  type EntityOptions,
  fullEntitiesList,
  internalFindByIdsMapped,
  pageEntitiesConnection,
  pageRegardingEntitiesConnection,
  storeLoadById,
} from '../../database/middleware-loader';
import { notify } from '../../database/redis';
import { publishUserAction } from '../../listener/UserActionListener';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../schema/general';
import { generateStandardId, getInputIds } from '../../schema/identifier';
import { ENTITY_TYPE_ATTACK_PATTERN, ENTITY_TYPE_CONTAINER_REPORT } from '../../schema/stixDomainObject';
import { RELATION_GRANTED_TO, RELATION_OBJECT, RELATION_OBJECT_MARKING } from '../../schema/stixRefRelationship';
import { now } from '../../utils/format';
import {
  type EditInput,
  FilterMode,
  type HuntAddInput,
  type HuntAssistField,
  type HuntAssistInput,
  type HuntPlanInput,
  HuntSourceKind,
  HuntStatus,
  HuntType,
  type HuntValidateFromEmulationInput,
  type InputMaybe,
  OrderingMode,
  PirRelationshipOrdering,
} from '../../generated/graphql';
import { stixDomainObjectEditField } from '../../domain/stixDomainObject';
import { checkEnterpriseEdition } from '../../enterprise-edition/ee';
import { addHuntPlanCount } from '../../manager/telemetryManager';
import { HUNT_MANAGER_USER, isUserHasCapability, KNOWLEDGE_ORGANIZATION_RESTRICT, MEMBER_ACCESS_RIGHT_ADMIN, MEMBER_ACCESS_RIGHT_EDIT, SYSTEM_USER } from '../../utils/access';
import { addDraftWorkspace } from '../draftWorkspace/draftWorkspace-domain';
import { ENTITY_TYPE_INDICATOR } from '../indicator/indicator-types';
import { ENTITY_TYPE_PIR } from '../pir/pir-types';
import { findPirRelationPaginated } from '../pir/pir-domain';
import { ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM, type BasicStoreEntitySecurityPlatform } from '../securityPlatform/securityPlatform-types';
import { ENTITY_TYPE_SECURITY_COVERAGE } from '../securityCoverage/securityCoverage-types';
import { resolveAgentJwtUser } from '../playbook/components/ai-agent-shared';
import {
  type BasicStoreEntityHunt,
  ENTITY_TYPE_HUNT,
  HUNT_SCHEDULE_MANUAL,
  HUNT_STATUS_ACTIVE,
  HUNT_TYPE_INDICATORS,
  INPUT_HUNT_TECHNIQUES,
  RELATION_HUNT_SOURCES,
  RELATION_HUNT_TARGETS,
  RELATION_HUNT_TECHNIQUES,
} from './hunt-types';
import { normalizeHuntIocValues, resolveHuntIocSet } from './hunt-iocs';
import { computeHuntReadiness, isUnmetReadinessItem } from './hunt-readiness';
import { HUNT_SOURCE_TYPES, HUNT_TARGET_TYPES } from './hunt-entity-types';
import { validateSigmaRule } from './hunt-sigma';
import { computeNextRunAt } from './hunt-schedule';
import { updateHuntRunInformation } from './hunt-stats';
import {
  buildHuntScopeFilter,
  HUNT_CONFIG,
  HUNT_DEFAULT_ESCALATION_THRESHOLD,
  HUNT_DEFAULT_TIME_WINDOW_HOURS,
  HUNT_MAX_ESCALATION_THRESHOLD,
  normalizeNativeQueries,
  sharedOrganizations,
} from './hunt-utils';
import { resolveHuntScopePlatforms } from './hunt-dispatch';
import {
  buildHuntAssistRequest,
  callHuntAgent,
  draftNativeQueries,
  HUNT_PLANNER_INTENT,
  HUNT_SIGMA_GENERATION_INTENT,
  huntAssistHasSubject,
  pickHuntAssistance,
  resolveHuntAssistTarget,
  validateHuntAssistDraft,
  validateHuntPlanSpec,
} from './hunt-agents';
import { parseHuntPack, planHuntPackImport, resolveHuntPackLabels } from './hunt-pack';
import { type HuntValidationState, mergeHuntEdits, validateHuntState } from './hunt-validators';
import { withHuntLock } from './hunt-lock';
import { filterEditableHunts } from './hunt-access';
import { cancelDeletedHuntRuns, createHuntRuns, findHuntConnectors, markHuntRunsOrphaned, startHuntTranslationCheck } from './huntRun/huntRun-domain';
import { type BasicStoreEntityHuntRun, ENTITY_TYPE_HUNT_RUN, HUNT_RUN_TRIGGER_EMULATION } from './huntRun/huntRun-types';

const ATTACK_TECHNIQUE_ID = /^T\d{4}(?:\.\d{3})?$/i;
const PLAN_MAX_ENTITIES = 50;
const PLAN_MAX_REPORT_OBJECTS = 50;
const PLAN_MAX_PIR_ENTITIES = 25;
const VALIDATION_LOCK = 'hunt_emulation_validation';

// region read
export const findHuntById = (context: AuthContext, user: AuthUser, id: string) => {
  return storeLoadById<BasicStoreEntityHunt>(context, user, id, ENTITY_TYPE_HUNT);
};

export const findHuntsPaginated = (context: AuthContext, user: AuthUser, args: EntityOptions<BasicStoreEntityHunt>) => {
  return pageEntitiesConnection<BasicStoreEntityHunt>(context, user, [ENTITY_TYPE_HUNT], {
    ...args,
    // The listed hunts resolve their targets, techniques, sources, readiness and values from these refs
    withoutRels: false,
  });
};

export const loadHuntRefs = async <T extends BasicStoreObject = BasicStoreObject>(context: AuthContext, user: AuthUser, hunt: BasicStoreEntityHunt, relation: string) => {
  const ids = (hunt[relation as keyof BasicStoreEntityHunt] ?? []) as string[];
  return findByIds<T>(context, user, ids);
};

export const loadHuntScopePlatforms = (context: AuthContext, user: AuthUser, hunt: BasicStoreEntityHunt) => {
  return resolveHuntScopePlatforms(context, user, hunt);
};

export const huntSigmaValidation = (hunt: BasicStoreEntityHunt) => {
  return hunt.sigma_rule && hunt.sigma_rule.trim().length > 0 ? validateSigmaRule(hunt.sigma_rule) : null;
};

const HUNT_IOC_SET_DEFAULT_FIRST = 50;

/** The values the next run of an indicator hunt looks up, the first ones listed. */
export const loadHuntIocSet = async (context: AuthContext, hunt: BasicStoreEntityHunt, first?: number | null) => {
  if (hunt.hunt_type !== HUNT_TYPE_INDICATORS) {
    return null;
  }
  const iocSet = await resolveHuntIocSet(context, hunt);
  const limit = Math.max(0, Math.min(first ?? HUNT_IOC_SET_DEFAULT_FIRST, HUNT_CONFIG.maxIocsPerRun));
  return { ...iocSet, iocs_count: iocSet.iocs.length, iocs: iocSet.iocs.slice(0, limit) };
};
// endregion

// region creation
/**
 * Resolves the techniques of a hunt: OpenCTI ids, standard ids or ATT&CK external ids (T1059.001).
 */
const resolveTechniqueIds = async (context: AuthContext, user: AuthUser, values: string[]) => {
  const attackIds = values.filter((value) => ATTACK_TECHNIQUE_ID.test(value)).map((value) => value.toUpperCase());
  const otherIds = values.filter((value) => !ATTACK_TECHNIQUE_ID.test(value));
  const byAttackId = attackIds.length > 0
    ? await fullEntitiesList<BasicStoreEntity & { x_mitre_id?: string }>(context, user, [ENTITY_TYPE_ATTACK_PATTERN], {
        filters: { mode: FilterMode.And, filters: [{ key: ['x_mitre_id'], values: attackIds }], filterGroups: [] },
      })
    : [];
  const unresolvedAttackIds = attackIds.filter((attackId) => !byAttackId.some((technique) => technique.x_mitre_id === attackId));
  if (unresolvedAttackIds.length > 0) {
    logApp.info('[OPENCTI-MODULE] Hunt techniques not found in the knowledge base', { attackIds: unresolvedAttackIds });
  }
  return [...otherIds, ...byAttackId.map((technique) => technique.internal_id)];
};

/** The techniques a hunt is linked to: the ones given, else those its Sigma rule is tagged with. */
const huntTechniqueIds = async (context: AuthContext, user: AuthUser, input: HuntAddInput) => {
  let techniques = input.huntTechniques ?? [];
  if (techniques.length === 0 && input.sigma_rule) {
    techniques = validateSigmaRule(input.sigma_rule).attack_techniques;
  }
  return techniques.length > 0 ? resolveTechniqueIds(context, user, techniques) : [];
};

export const normalizeHuntInput = async (context: AuthContext, user: AuthUser, input: HuntAddInput): Promise<HuntAddInput> => {
  const normalized: HuntAddInput = {
    ...input,
    hunt_type: input.hunt_type ?? HuntType.Telemetry,
    hunt_source_kind: input.hunt_source_kind ?? HuntSourceKind.Analyst,
    hunt_status: input.hunt_status ?? HuntStatus.Active,
    hunt_schedule: input.hunt_schedule?.trim() || HUNT_SCHEDULE_MANUAL,
    time_window_hours: input.time_window_hours ?? HUNT_DEFAULT_TIME_WINDOW_HOURS,
    escalation_threshold: input.escalation_threshold ?? HUNT_DEFAULT_ESCALATION_THRESHOLD,
    escalate_manual_runs: input.escalate_manual_runs ?? false,
    native_queries: normalizeNativeQueries(input.native_queries),
    hunt_ioc_values: normalizeHuntIocValues(input.hunt_ioc_values),
  };
  normalized.huntTechniques = await huntTechniqueIds(context, user, input);
  return normalized;
};

const refreshNextRunAt = async (context: AuthContext, hunt: BasicStoreEntityHunt) => {
  const nextRunAt = hunt.hunt_status === HUNT_STATUS_ACTIVE ? computeNextRunAt(hunt.hunt_schedule, new Date()) : null;
  await updateHuntRunInformation(context, hunt.internal_id, { next_run_at: nextRunAt ? nextRunAt.toISOString() : null });
};

export const addHunt = async (context: AuthContext, user: AuthUser, input: HuntAddInput, opts: { upsertedStatus?: string | null } = {}) => {
  const huntInput = await normalizeHuntInput(context, user, input);
  // Creating an active hunt activates it, so its readiness applies as on any activation: an explicitly active hunt that
  // cannot run is refused with the sentence of the first unmet item, one created without a status starts as a draft.
  // Upserting a hunt already active (a hunt pack imported again) activates nothing, and a STIX import or a
  // synchronization replicates a hunt that exists elsewhere with its status, the hunt manager only running ready hunts.
  const replicated = !!input.stix_id || context.synchronizedUpsert === true;
  if (!context.draft_context && !replicated && huntInput.hunt_status === HuntStatus.Active && opts.upsertedStatus !== HUNT_STATUS_ACTIVE) {
    const readiness = await computeHuntReadiness(context, user, { ...huntInput, [RELATION_HUNT_SOURCES]: huntInput.huntSources ?? [] } as unknown as BasicStoreEntityHunt);
    const unmet = readiness.items.find(isUnmetReadinessItem);
    if (unmet && input.hunt_status) {
      throw ValidationError(`This hunt cannot be activated: ${unmet.message}`, 'hunt_status');
    }
    if (unmet) {
      huntInput.hunt_status = HuntStatus.Draft;
    }
  }
  const created = await createEntity(context, user, huntInput, ENTITY_TYPE_HUNT) as BasicStoreEntityHunt;
  if (!context.draft_context) {
    await refreshNextRunAt(context, created);
  }
  // A hunt created explicitly active is activated: its translation is checked as on any activation
  const activated = input.hunt_status === HuntStatus.Active && created.hunt_status === HUNT_STATUS_ACTIVE && opts.upsertedStatus !== HUNT_STATUS_ACTIVE;
  if (!context.draft_context && !replicated && activated) {
    await startHuntTranslationCheck(context, user, created);
  }
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};

/**
 * Draft-first creation used by agents: a draft workspace is created and the hunt is created inside it, the
 * existing draft approval workflow validates it into the knowledge graph. Like a planned hunt, the proposal carries the
 * markings of the threats, techniques, indicators and reports it references and is shared only with the organizations
 * they all share: a hunt derived from restricted intelligence is never proposed less restricted, whatever the caller
 * asked for.
 */
export const addHuntProposal = async (context: AuthContext, user: AuthUser, input: HuntAddInput, draftName?: string | null) => {
  const techniqueIds = await huntTechniqueIds(context, user, input);
  const referenceIds = [...(input.huntTargets ?? []), ...(input.huntSources ?? []), ...techniqueIds];
  const references = referenceIds.length > 0 ? await findByIds<BasicStoreEntity>(context, user, referenceIds) : [];
  const inheritedMarkings = references.flatMap((reference) => (reference[RELATION_OBJECT_MARKING] ?? []) as string[]);
  const objectMarking = Array.from(new Set([...(input.objectMarking ?? []), ...inheritedMarkings]));
  const requestedOrganizations = (input.objectOrganization ?? []).filter((id): id is string => !!id);
  // No organization asked for is no restriction asked for: only the references then restrict the proposal
  const objectOrganization = sharedOrganizations([
    ...(requestedOrganizations.length > 0 ? [requestedOrganizations] : []),
    ...references.map((reference) => (reference[RELATION_GRANTED_TO] ?? []) as string[]),
  ]);
  if (!objectOrganization) {
    throw FunctionalError('This hunt cannot be proposed: the intelligence it references is shared with organizations that have none in common. Reference intelligence shared with a common organization.');
  }
  // Without this capability the organizations of an object are not the ones given but those of its creator
  if (objectOrganization.length > 0 && !isUserHasCapability(user, KNOWLEDGE_ORGANIZATION_RESTRICT)) {
    throw FunctionalError('This hunt cannot be proposed: the intelligence it references is restricted to organizations, and only a user who can restrict access to organizations can propose it.');
  }
  // The workspace is listed to every user with draft access, the hunt inside only to the readers of its markings and
  // organizations: a restricted proposal gets neutral workspace metadata, never its name, hypothesis or plan name
  const restricted = objectMarking.length > 0 || objectOrganization.length > 0;
  const draft = await addDraftWorkspace(context, user, {
    ...(restricted ? {
      name: `Hunt proposal - ${now()}`,
      description: 'Hunt proposed by an agent from restricted intelligence. Open the draft to review the hunt, validate it to create the hunt.',
    } : {
      name: (draftName?.trim() || `Hunt proposal - ${input.name}`).substring(0, 250),
      description: input.hypothesis ? `Proposed hunt hypothesis: ${input.hypothesis}` : undefined,
    }),
    ...(objectOrganization.length > 0 ? {
      authorized_members: [
        { id: user.id, access_right: MEMBER_ACCESS_RIGHT_ADMIN },
        ...objectOrganization.map((id) => ({ id, access_right: MEMBER_ACCESS_RIGHT_EDIT })),
      ],
    } : {}),
  });
  const draftContext: AuthContext = { ...context, draft_context: draft.id };
  // A proposal is always a draft hunt, whatever status its input carries: validating the workspace creates it, an
  // analyst activates it
  const hunt = await addHunt(draftContext, user, {
    ...input,
    huntTechniques: techniqueIds,
    objectMarking,
    objectOrganization,
    hunt_status: HuntStatus.Draft,
    hunt_source_kind: input.hunt_source_kind ?? HuntSourceKind.Agent,
  });
  return { draft_id: draft.id, hunt };
};

export const huntDelete = async (context: AuthContext, user: AuthUser, huntId: string) => {
  const hunt = await findHuntById(context, user, huntId);
  if (!hunt) {
    throw ResourceNotFoundError('Hunt cannot be found', { huntId });
  }
  // Runs are kept so that a hunt restored from the trash keeps its history, the run retention purges them; those still
  // waiting or running are cancelled, so that they free the slots of their connectors, and all leave the statistics.
  // The hunt manager does the same for a hunt deleted otherwise, and brings back the runs of a restored hunt
  await deleteElementById(context, user, hunt.internal_id, ENTITY_TYPE_HUNT);
  if (!context.draft_context) {
    await cancelDeletedHuntRuns(context, hunt.internal_id);
    await markHuntRunsOrphaned([hunt.internal_id], true)
      .catch((error) => logApp.warn('[OPENCTI-MODULE] Runs of a deleted hunt not marked, the hunt manager marks them at its next pass', { cause: error, huntId: hunt.internal_id }));
  }
  await notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].DELETE_TOPIC, huntId, user);
  return huntId;
};

export const huntEditField = async (
  context: AuthContext,
  user: AuthUser,
  huntId: string,
  rawInput: InputMaybe<EditInput>[],
  opts: { commitMessage?: string | null; references?: InputMaybe<string>[] | null } = {},
) => {
  const input = rawInput.filter((editInput): editInput is EditInput => !!editInput);
  const normalizedInput = input.map((editInput) => {
    if (editInput.key === 'native_queries') {
      return { ...editInput, value: normalizeNativeQueries(editInput.value) };
    }
    if (editInput.key === 'hunt_ioc_values') {
      return { ...editInput, value: normalizeHuntIocValues(editInput.value) };
    }
    return editInput;
  });
  // Activating (or resuming) a hunt requires every item of its readiness, refused with the sentence of the first unmet
  // one; inside a draft workspace the hunt only runs once the draft is validated, its logic is checked at the edit
  const activation = normalizedInput.find((editInput) => editInput.key === 'hunt_status');
  let activated = false;
  if (activation && (activation.value ?? [])[0] === HUNT_STATUS_ACTIVE && !context.draft_context) {
    const current = await findHuntById(context, user, huntId);
    if (current && current.hunt_status !== HUNT_STATUS_ACTIVE) {
      const readiness = await computeHuntReadiness(context, user, mergeHuntEdits(current, normalizedInput));
      const unmet = readiness.items.find(isUnmetReadinessItem);
      if (unmet) {
        throw ValidationError(`This hunt cannot be activated: ${unmet.message}`, 'hunt_status');
      }
      activated = true;
    }
  }
  const updated = await stixDomainObjectEditField(context, user, huntId, normalizedInput, opts) as BasicStoreEntityHunt;
  if (!context.draft_context && input.some((editInput) => ['hunt_schedule', 'hunt_status'].includes(editInput.key))) {
    await refreshNextRunAt(context, updated);
  }
  if (activated) {
    await startHuntTranslationCheck(context, user, updated);
  }
  return updated;
};
// endregion

// region planning (XTM One cti.hunt_hypothesis)
const toPlanThreat = (entity: BasicStoreEntity & Record<string, any>) => ({
  id: entity.internal_id,
  standard_id: entity.standard_id,
  entity_type: entity.entity_type,
  name: entity.name,
  description: entity.description ?? '',
  aliases: entity.aliases ?? entity.x_opencti_aliases ?? [],
});

/** The threats, techniques and indicators a hunt is planned for: the entities themselves, the flagged threats of a PIR, the knowledge a report contains. */
export const loadHuntPlanEntities = async (context: AuthContext, user: AuthUser, entityIds: string[]) => {
  const knowledge = await findByIds<BasicStoreEntity & Record<string, any>>(context, user, entityIds);
  const foundIds = new Set(knowledge.map((element) => element.internal_id));
  const entities = [...knowledge];
  // PIR: the most relevant flagged threats of the PIR are planned for
  const pirIds = entityIds.filter((id) => !foundIds.has(id));
  for (let index = 0; index < pirIds.length; index += 1) {
    const pir = await storeLoadById<BasicStoreEntity>(context, user, pirIds[index], ENTITY_TYPE_PIR).catch(() => null);
    if (pir) {
      const flagged = await findPirRelationPaginated(context, user, {
        pirId: pir.internal_id,
        first: PLAN_MAX_PIR_ENTITIES,
        orderBy: PirRelationshipOrdering.PirScore,
        orderMode: OrderingMode.Desc,
      });
      const flaggedIds = flagged.edges.map((edge: { node: { fromId: string } }) => edge.node.fromId);
      entities.push(...(flaggedIds.length > 0 ? await findByIds<BasicStoreEntity & Record<string, any>>(context, user, flaggedIds) : []));
    }
  }
  // Reports: the threats, techniques and indicators they contain, read through their object relationships (a
  // stored report does not carry its object refs)
  const reports = entities.filter((entity) => entity.entity_type === ENTITY_TYPE_CONTAINER_REPORT);
  const plannedTypes = [...HUNT_TARGET_TYPES, ENTITY_TYPE_ATTACK_PATTERN, ENTITY_TYPE_INDICATOR];
  for (let index = 0; index < reports.length; index += 1) {
    const contained = await pageRegardingEntitiesConnection<BasicStoreEntity & Record<string, any>>(
      context,
      user,
      reports[index].internal_id,
      RELATION_OBJECT,
      plannedTypes,
      false,
      { first: PLAN_MAX_REPORT_OBJECTS },
    );
    entities.push(...contained.edges.map((edge) => edge.node));
  }
  const unique = Array.from(new Map(entities.map((entity) => [entity.internal_id, entity])).values());
  return {
    entities: unique,
    reports,
    threats: unique.filter((entity) => HUNT_TARGET_TYPES.includes(entity.entity_type)),
    techniques: unique.filter((entity) => entity.entity_type === ENTITY_TYPE_ATTACK_PATTERN),
    indicators: unique.filter((entity) => entity.entity_type === ENTITY_TYPE_INDICATOR),
  };
};

/**
 * Internal ids of the Security Platforms a hunt is explicitly planned for. Each must resolve for the user: the
 * proposed hunt is scoped to them, and an empty scope would run it on every platform.
 */
export const resolveHuntPlanPlatformIds = async (context: AuthContext, user: AuthUser, platformIds: string[]) => {
  const requested = Array.from(new Set(platformIds));
  if (requested.length === 0) {
    return [];
  }
  const platforms = await internalFindByIdsMapped<BasicStoreEntitySecurityPlatform>(context, user, requested, {
    type: ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM,
    mapWithAllIds: true,
  });
  const missing = requested.filter((id) => !platforms[id]);
  if (missing.length > 0) {
    throw FunctionalError('A security platform the hunt is planned for cannot be found', { security_platform_ids: missing });
  }
  return Array.from(new Set(requested.map((id) => platforms[id].internal_id)));
};

type HuntPlanKnowledge = Omit<Awaited<ReturnType<typeof loadHuntPlanEntities>>, 'entities'>;

/** The cti.hunt_hypothesis request: the knowledge to plan from and the platforms of the live hunt connectors, with their query languages. */
const buildHuntPlannerRequest = async (
  context: AuthContext,
  user: AuthUser,
  { reports, threats, techniques, indicators }: HuntPlanKnowledge,
  scopePlatformIds: string[],
  benignPatterns: string[],
) => {
  const connectors = await findHuntConnectors(context, true);
  const requestedPlatforms = new Set(scopePlatformIds);
  const platformIds = connectors
    .map((connector) => connector.security_platform_id)
    .filter((id): id is string => !!id && (requestedPlatforms.size === 0 || requestedPlatforms.has(id)));
  const platforms = platformIds.length > 0
    ? await findByIds<BasicStoreEntitySecurityPlatform>(context, user, platformIds, { type: ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM })
    : [];
  return {
    task: 'hunt_hypothesis',
    threats: threats.map(toPlanThreat),
    techniques: techniques.map((technique) => ({
      id: technique.internal_id,
      standard_id: technique.standard_id,
      x_mitre_id: technique.x_mitre_id ?? null,
      name: technique.name,
      description: technique.description ?? '',
      platforms: technique.x_mitre_platforms ?? [],
    })),
    indicators: indicators.map((indicator) => ({ id: indicator.internal_id, name: indicator.name, pattern_type: indicator.pattern_type, pattern: indicator.pattern })),
    reports: reports.map((report) => ({ id: report.internal_id, name: report.name, description: report.description ?? '' })),
    security_platforms: platforms.map((platform) => {
      const connector = connectors.find((c) => c.security_platform_id === platform.internal_id);
      return {
        id: platform.internal_id,
        name: platform.name,
        security_platform_type: platform.security_platform_type,
        platform: connector?.platform,
        languages: connector?.languages ?? [],
      };
    }),
    benign_patterns: benignPatterns,
    // The limits the plan is validated against
    constraints: { max_time_window_hours: HUNT_CONFIG.maxTimeWindowHours, max_escalation_threshold: HUNT_MAX_ESCALATION_THRESHOLD },
  };
};

export const planHunt = async (context: AuthContext, user: AuthUser, input: HuntPlanInput) => {
  await checkEnterpriseEdition(context);
  if (input.entity_ids.length === 0 || input.entity_ids.length > PLAN_MAX_ENTITIES) {
    throw FunctionalError(`A hunt is planned from 1 to ${PLAN_MAX_ENTITIES} entities`);
  }
  const scopePlatformIds = await resolveHuntPlanPlatformIds(context, user, input.security_platform_ids ?? []);
  const { entities: unique, reports, threats, techniques, indicators } = await loadHuntPlanEntities(context, user, input.entity_ids);
  if (threats.length + techniques.length + indicators.length === 0) {
    throw FunctionalError('No threat, technique or indicator to plan a hunt for');
  }
  const payload = await buildHuntPlannerRequest(context, user, { reports, threats, techniques, indicators }, scopePlatformIds, input.benign_patterns ?? []);
  const jwtUser = await resolveAgentJwtUser(user.id);
  const { answer } = await callHuntAgent(HUNT_PLANNER_INTENT, jwtUser, payload, input.agent_slug);
  const spec = validateHuntPlanSpec(answer, threats.map((threat) => threat.internal_id));
  addHuntPlanCount();
  // The hunt inherits the markings of the knowledge it was planned from
  const markingIds = Array.from(new Set(unique.flatMap((entity) => (entity[RELATION_OBJECT_MARKING] ?? []) as string[])));
  const huntType = spec.hunt_type === HuntType.Infrastructure ? HuntType.Infrastructure : HuntType.Telemetry;
  const huntInput: HuntAddInput = {
    name: spec.name,
    description: [spec.description, spec.rationale ? `Rationale: ${spec.rationale}` : ''].filter((part) => part.length > 0).join('\n\n'),
    hypothesis: spec.hypothesis,
    hunt_type: huntType,
    // An infrastructure hunt runs on the internet platform, never on a security platform
    hunt_scope: huntType === HuntType.Telemetry ? buildHuntScopeFilter(scopePlatformIds) : '',
    // Validating the draft workspace creates the hunt; an analyst then activates it from its readiness checklist
    hunt_status: HuntStatus.Draft,
    hunt_source_kind: HuntSourceKind.Agent,
    sigma_rule: spec.sigma_rule,
    native_queries: spec.native_queries,
    expected_observables: spec.expected_observables,
    benign_patterns: Array.from(new Set([...spec.benign_patterns, ...(input.benign_patterns ?? [])])),
    escalation_threshold: spec.escalation_threshold,
    time_window_hours: spec.time_window_hours,
    huntTechniques: [...techniques.map((technique) => technique.internal_id), ...spec.technique_ids],
    huntTargets: spec.target_ids.length > 0 ? spec.target_ids : threats.map((threat) => threat.internal_id),
    huntSources: [...indicators, ...reports].filter((entity) => HUNT_SOURCE_TYPES.includes(entity.entity_type)).map((entity) => entity.internal_id),
    objectMarking: markingIds,
  };
  const proposal = await addHuntProposal(context, user, huntInput, `Hunt plan - ${spec.name}`);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'create',
    event_access: 'extended',
    message: `plans hunt \`${spec.name}\` with XTM One`,
    context_data: { id: proposal.hunt.internal_id, entity_type: ENTITY_TYPE_HUNT, input: { entity_ids: input.entity_ids, draft_id: proposal.draft_id } },
  });
  return proposal;
};
// endregion

// region assistance of a hunt being written (XTM One cti.hunt_hypothesis and cti.hunt_sigma_generation)
/** The Attack Patterns of the platform the agent named by their ATT&CK ids, in the order it named them. */
const resolveAssistTechniques = async (context: AuthContext, user: AuthUser, attackIds: string[]) => {
  if (attackIds.length === 0) {
    return { techniques: [], unknown: [] };
  }
  const found = await fullEntitiesList<BasicStoreEntity & { x_mitre_id?: string; name: string }>(context, user, [ENTITY_TYPE_ATTACK_PATTERN], {
    filters: { mode: FilterMode.And, filters: [{ key: ['x_mitre_id'], values: attackIds }], filterGroups: [] },
  });
  const byAttackId = new Map(found.map((technique) => [(technique.x_mitre_id ?? '').toUpperCase(), technique]));
  return {
    techniques: attackIds.filter((id) => byAttackId.has(id)).map((id) => {
      const technique = byAttackId.get(id) as BasicStoreEntity & { x_mitre_id?: string; name: string };
      return { id: technique.internal_id, entity_type: technique.entity_type, name: technique.name, x_mitre_id: technique.x_mitre_id ?? null };
    }),
    unknown: attackIds.filter((id) => !byAttackId.has(id)),
  };
};

/**
 * What XTM One proposes for the fields of a hunt being written - or for the whole plan when no field is asked - from
 * everything the form holds, the saved hunt and the knowledge of the platform. Nothing is saved: the analyst accepts
 * the proposal field by field.
 */
export const assistHunt = async (context: AuthContext, user: AuthUser, input: HuntAssistInput) => {
  await checkEnterpriseEdition(context);
  const target = resolveHuntAssistTarget(input.fields ?? [], { platform: input.native_query_platform, language: input.native_query_language });
  const hunt = input.hunt_id ? await storeLoadById<BasicStoreEntityHunt>(context, user, input.hunt_id, ENTITY_TYPE_HUNT) : null;
  if (input.hunt_id && !hunt) {
    throw ResourceNotFoundError('The hunt cannot be found', { id: input.hunt_id });
  }
  const draft = validateHuntAssistDraft({
    name: (input.name ?? hunt?.name ?? '').trim(),
    hunt_type: input.hunt_type ?? hunt?.hunt_type ?? HuntType.Telemetry,
    hypothesis: (input.hypothesis ?? hunt?.hypothesis ?? '').trim(),
    description: (input.description ?? hunt?.description ?? '').trim(),
    sigma_rule: (input.sigma_rule ?? hunt?.sigma_rule ?? '').trim(),
    native_queries: draftNativeQueries(input.native_queries ?? hunt?.native_queries ?? []),
    expected_observables: input.expected_observables ?? hunt?.expected_observables ?? [],
    benign_patterns: input.benign_patterns ?? hunt?.benign_patterns ?? [],
    prompt: (input.prompt ?? '').trim(),
  });
  const entityIds = Array.from(new Set([
    ...(input.target_ids ?? hunt?.[RELATION_HUNT_TARGETS] ?? []),
    ...(input.technique_ids ?? hunt?.[RELATION_HUNT_TECHNIQUES] ?? []),
    ...(input.source_ids ?? hunt?.[RELATION_HUNT_SOURCES] ?? []),
  ]));
  if (entityIds.length > PLAN_MAX_ENTITIES) {
    throw FunctionalError(`A hunt is written from at most ${PLAN_MAX_ENTITIES} threats, techniques, indicators and reports`);
  }
  if (!huntAssistHasSubject(draft, entityIds.length)) {
    throw FunctionalError('Say what to hunt: a name, a few words, a hypothesis, a threat or a technique');
  }
  let scopePlatformIds: string[] = [];
  if (input.security_platform_ids) {
    scopePlatformIds = await resolveHuntPlanPlatformIds(context, user, input.security_platform_ids);
  } else if (hunt?.hunt_scope) {
    scopePlatformIds = (await resolveHuntScopePlatforms(context, user, hunt)).map((platform) => platform.internal_id);
  }
  const knowledge = entityIds.length > 0
    ? await loadHuntPlanEntities(context, user, entityIds)
    : { reports: [], threats: [], techniques: [], indicators: [] };
  const plannerRequest = await buildHuntPlannerRequest(context, user, knowledge, scopePlatformIds, draft.benign_patterns);
  const payload = buildHuntAssistRequest(plannerRequest, draft, target);
  const sigmaOnly = payload.task === 'hunt_sigma_generation';
  const jwtUser = await resolveAgentJwtUser(user.id);
  const { slug, answer } = await callHuntAgent(sigmaOnly ? HUNT_SIGMA_GENERATION_INTENT : HUNT_PLANNER_INTENT, jwtUser, payload, input.agent_slug);
  const proposal = pickHuntAssistance(validateHuntPlanSpec(answer, knowledge.threats.map((threat) => threat.internal_id)), target);
  const { techniques, unknown } = await resolveAssistTechniques(context, user, proposal.technique_ids);
  if (target.fields.length === 0) {
    addHuntPlanCount();
  }
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: hunt ? 'update' : 'create',
    event_access: 'extended',
    message: target.fields.length === 0
      ? `plans hunt \`${draft.name || proposal.name}\` with XTM One`
      : `writes the ${target.fields.join(', ')} of hunt \`${draft.name || proposal.name}\` with XTM One`,
    context_data: {
      id: hunt?.internal_id ?? '',
      entity_type: ENTITY_TYPE_HUNT,
      input: { agent_slug: slug, fields: target.fields, target_ids: input.target_ids, technique_ids: input.technique_ids, security_platform_ids: input.security_platform_ids },
    },
  });
  return { ...proposal, fields: proposal.fields as string[] as HuntAssistField[], techniques, unknown_technique_ids: unknown };
};
// endregion

// region OpenAEV emulation validation
const resolveEmulationTechnique = async (context: AuthContext, user: AuthUser, techniqueId: string) => {
  if (ATTACK_TECHNIQUE_ID.test(techniqueId)) {
    const [technique] = await fullEntitiesList<BasicStoreEntity>(context, user, [ENTITY_TYPE_ATTACK_PATTERN], {
      filters: { mode: FilterMode.And, filters: [{ key: ['x_mitre_id'], values: [techniqueId.toUpperCase()] }], filterGroups: [] },
    });
    return technique ?? null;
  }
  return storeLoadById<BasicStoreEntity>(context, user, techniqueId, ENTITY_TYPE_ATTACK_PATTERN);
};

const resolveEmulationPlatform = async (context: AuthContext, user: AuthUser, input: HuntValidateFromEmulationInput) => {
  if (input.security_platform_id) {
    const platform = await storeLoadById<BasicStoreEntitySecurityPlatform>(context, user, input.security_platform_id, ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM);
    if (platform) {
      return platform;
    }
  }
  if (input.security_platform_name) {
    const [platform] = await fullEntitiesList<BasicStoreEntitySecurityPlatform>(context, user, [ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM], {
      filters: { mode: FilterMode.And, filters: [{ key: ['name'], values: [input.security_platform_name] }], filterGroups: [] },
    });
    return platform ?? null;
  }
  return null;
};

/**
 * OpenAEV validation loop: an inject emulating a technique completed on an asset monitored by a security platform.
 * Every active hunt covering the technique runs on that platform over the emulation window (idempotent per
 * inject, technique, hunt, platform and security coverage: an inject emulating several techniques, or validated for
 * several security coverages, gets runs of its own for each). Completed runs write coverage_information hunt_detected
 * on the security coverage.
 */
export const huntValidateFromEmulation = async (context: AuthContext, user: AuthUser, input: HuntValidateFromEmulationInput) => {
  await checkEnterpriseEdition(context);
  const windowStart = new Date(input.window_start);
  const windowEnd = new Date(input.window_end);
  if (Number.isNaN(windowStart.getTime()) || Number.isNaN(windowEnd.getTime()) || windowStart.getTime() >= windowEnd.getTime()) {
    throw FunctionalError('The emulation window is invalid', { window_start: input.window_start, window_end: input.window_end });
  }
  const technique = await resolveEmulationTechnique(context, user, input.technique_id);
  if (!technique) {
    throw ResourceNotFoundError('The emulated technique cannot be found', { techniqueId: input.technique_id });
  }
  const platform = await resolveEmulationPlatform(context, user, input);
  if (!platform) {
    throw ResourceNotFoundError('The security platform of the emulation cannot be found', { securityPlatformId: input.security_platform_id, securityPlatformName: input.security_platform_name });
  }
  let securityCoverageId: string | null = null;
  if (input.security_coverage_id) {
    const coverage = await storeLoadById<BasicStoreEntity>(context, user, input.security_coverage_id, ENTITY_TYPE_SECURITY_COVERAGE);
    // Runs of an unknown coverage would be validations whose result no coverage ever receives
    if (!coverage) {
      throw ResourceNotFoundError('The security coverage of the emulation cannot be found', { securityCoverageId: input.security_coverage_id });
    }
    securityCoverageId = coverage.internal_id;
  }
  // Every active hunt covering the technique, read page by page in a stable order
  const coveringHunts = await fullEntitiesList<BasicStoreEntityHunt>(context, user, [ENTITY_TYPE_HUNT], {
    filters: {
      mode: FilterMode.And,
      filters: [
        { key: ['hunt_status'], values: [HUNT_STATUS_ACTIVE] },
        { key: [INPUT_HUNT_TECHNIQUES], values: [technique.internal_id] },
      ],
      filterGroups: [],
    },
    orderBy: 'created_at',
    orderMode: OrderingMode.Asc,
    // The dispatched runs carry the techniques, targets and sources of the hunts
    withoutRels: false,
  });
  // Running a hunt changes it: the hunts the caller can only read are left out
  const hunts = await filterEditableHunts(context, user, coveringHunts);
  // Retries of the same inject and technique on the same platform are serialized, so the runs already created are always seen
  const runs = await withHuntLock(`${VALIDATION_LOCK}_${input.inject_id}_${technique.internal_id}_${platform.internal_id}`, async () => {
    const existingRuns = await fullEntitiesList<BasicStoreEntityHuntRun>(context, HUNT_MANAGER_USER, [ENTITY_TYPE_HUNT_RUN], {
      filters: {
        mode: FilterMode.And,
        filters: [
          { key: ['aev_inject_id'], values: [input.inject_id] },
          { key: ['technique_id'], values: [technique.internal_id] },
          { key: ['security_platform_id'], values: [platform.internal_id] },
          { key: ['hunt_run_trigger'], values: [HUNT_RUN_TRIGGER_EMULATION] },
        ],
        filterGroups: [],
      },
      noFiltersChecking: true,
    });
    const validationRuns: BasicStoreEntityHuntRun[] = [];
    for (let index = 0; index < hunts.length; index += 1) {
      const hunt = hunts[index];
      const existing = existingRuns.filter((run) => run.hunt_id === hunt.internal_id && (run.security_coverage_id ?? null) === securityCoverageId);
      if (existing.length > 0) {
        validationRuns.push(...existing);
      } else {
        const created = await createHuntRuns(context, hunt, {
          trigger: HUNT_RUN_TRIGGER_EMULATION,
          securityPlatformIds: [platform.internal_id],
          windowStart: windowStart.toISOString(),
          windowEnd: windowEnd.toISOString(),
          aevInjectId: input.inject_id,
          securityCoverageId,
          techniqueId: technique.internal_id,
          triggeredBy: user.id,
        });
        validationRuns.push(...created);
      }
    }
    return validationRuns;
  });
  logApp.info('[OPENCTI-MODULE] Hunt validation from emulation', { injectId: input.inject_id, technique: technique.internal_id, platform: platform.internal_id, hunts: hunts.length, runs: runs.length });
  return { hunts_count: hunts.length, runs };
};
// endregion

// region hunt packs
const HUNT_PACK_LOCAL_FIELDS = ['hunt_status', 'hunt_source_kind', 'hunt_schedule', 'hunt_scope', 'trigger_filters', 'hunt_pir_activation'] as const;

// The local hunt the creation of a pack hunt upserts: it resolves the same ids as the creation (the name identity and
// the STIX ID), so a pack hunt carrying another STIX ID under the name of a local hunt is still that local hunt
const resolveHuntPackExistingHunt = async (context: AuthContext, user: AuthUser, input: Record<string, unknown>) => {
  const ids = getInputIds(ENTITY_TYPE_HUNT, { ...input, entity_type: ENTITY_TYPE_HUNT }, false);
  const existing = await findByIds<BasicStoreEntityHunt>(context, user, ids, { type: ENTITY_TYPE_HUNT });
  if (existing.length === 0) {
    // The creation would find this hunt and refuse it in the middle of the pack: refuse it before the first write
    const restricted = await findByIds<BasicStoreEntityHunt>(context, SYSTEM_USER, ids, { type: ENTITY_TYPE_HUNT });
    if (restricted.length > 0) {
      throw UnsupportedError('Restricted entity already exists', { doc_code: 'RESTRICTED_ELEMENT', name: input.name });
    }
    return undefined;
  }
  const standardId = generateStandardId(ENTITY_TYPE_HUNT, input);
  return existing.find((hunt) => hunt.standard_id === standardId) ?? existing[0];
};

export const importHuntPack = async (context: AuthContext, user: AuthUser, file: Promise<FileHandle>) => {
  const { hunts, objects } = await parseHuntPack(file);
  const unresolved = new Set<string>();
  // Every hunt of the pack is planned and checked before the first write: a refused hunt fails the import with
  // nothing written, neither the hunts before it nor their labels
  const prepared: { input: Record<string, unknown>; labels: string[]; existing: boolean; existingStatus: string | null }[] = [];
  const preparedStandardIds = new Set<string>();
  for (let index = 0; index < hunts.length; index += 1) {
    const plan = await planHuntPackImport(context, user, hunts[index], objects);
    plan.unresolved.forEach((ref) => unresolved.add(ref));
    if (plan.blocked) {
      logApp.warn('[OPENCTI-MODULE] Hunt pack hunt skipped, its markings or organizations are unknown on this platform', { hunt: hunts[index].id });
    } else {
      // A pack updates the definition of a hunt that exists here, never how it runs here (status, origin, schedule)
      const input = { ...plan.input };
      // Two hunts of one pack with the same name are one hunt here: the second would silently replace the first
      const standardId = generateStandardId(ENTITY_TYPE_HUNT, input);
      if (preparedStandardIds.has(standardId)) {
        throw FunctionalError('A hunt pack cannot hold two hunts with the same name', { name: input.name });
      }
      preparedStandardIds.add(standardId);
      const existing = await resolveHuntPackExistingHunt(context, user, input);
      if (existing) {
        HUNT_PACK_LOCAL_FIELDS.forEach((field) => {
          input[field] = existing[field];
        });
      }
      await validateHuntState(context, input as HuntValidationState);
      prepared.push({ input, labels: plan.labels, existing: !!existing, existingStatus: existing?.hunt_status ?? null });
    }
  }
  const imported: BasicStoreEntityHunt[] = [];
  let updatedCount = 0;
  for (let index = 0; index < prepared.length; index += 1) {
    const { input, labels, existing, existingStatus } = prepared[index];
    input.objectLabel = await resolveHuntPackLabels(context, user, labels);
    imported.push(await addHunt(context, user, input as unknown as HuntAddInput, { upsertedStatus: existingStatus }));
    if (existing) {
      updatedCount += 1;
    }
  }
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'create',
    event_access: 'extended',
    message: `imports a hunt pack of ${imported.length} hunt(s)`,
    context_data: { id: imported[0]?.internal_id ?? '', entity_type: ENTITY_TYPE_HUNT, input: { hunts: hunts.length } },
  });
  return { hunts: imported, unresolved_refs: Array.from(unresolved), created_count: imported.length - updatedCount, updated_count: updatedCount };
};
// endregion
