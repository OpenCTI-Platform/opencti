import { findByIds } from './hunt-loaders';
import type { FileHandle } from 'fs/promises';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreEntity, BasicStoreObject } from '../../types/store';
import { BUS_TOPICS, logApp } from '../../config/conf';
import { FunctionalError, ResourceNotFoundError } from '../../config/errors';
import { createEntity, deleteElementById } from '../../database/middleware';
import { type EntityOptions, fullEntitiesList, pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
import { notify } from '../../database/redis';
import { publishUserAction } from '../../listener/UserActionListener';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../schema/general';
import { ENTITY_TYPE_ATTACK_PATTERN, ENTITY_TYPE_CONTAINER_REPORT } from '../../schema/stixDomainObject';
import { RELATION_OBJECT, RELATION_OBJECT_MARKING } from '../../schema/stixRefRelationship';
import {
  type EditInput,
  FilterMode,
  type HuntAddInput,
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
import { HUNT_MANAGER_USER } from '../../utils/access';
import { addDraftWorkspace } from '../draftWorkspace/draftWorkspace-domain';
import { ENTITY_TYPE_INDICATOR } from '../indicator/indicator-types';
import { ENTITY_TYPE_PIR } from '../pir/pir-types';
import { findPirRelationPaginated } from '../pir/pir-domain';
import { ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM, type BasicStoreEntitySecurityPlatform } from '../securityPlatform/securityPlatform-types';
import { ENTITY_TYPE_SECURITY_COVERAGE } from '../securityCoverage/securityCoverage-types';
import { resolveAgentJwtUser } from '../playbook/components/ai-agent-shared';
import { type BasicStoreEntityHunt, ENTITY_TYPE_HUNT, HUNT_SCHEDULE_MANUAL, HUNT_STATUS_ACTIVE, RELATION_HUNT_TECHNIQUES } from './hunt-types';
import { HUNT_SOURCE_TYPES, HUNT_TARGET_TYPES } from './hunt';
import { validateSigmaRule } from './hunt-sigma';
import { computeNextRunAt } from './hunt-schedule';
import { updateHuntRunInformation } from './hunt-stats';
import { HUNT_DEFAULT_ESCALATION_THRESHOLD, HUNT_DEFAULT_TIME_WINDOW_HOURS, normalizeNativeQueries } from './hunt-utils';
import { resolveHuntScopePlatforms } from './hunt-dispatch';
import { callHuntAgent, HUNT_PLANNER_INTENT, validateHuntPlanSpec } from './hunt-agents';
import { parseHuntPack, planHuntPackImport } from './hunt-pack';
import { createHuntRuns, findHuntConnectors } from './huntRun/huntRun-domain';
import { type BasicStoreEntityHuntRun, ENTITY_TYPE_HUNT_RUN, HUNT_RUN_TRIGGER_EMULATION } from './huntRun/huntRun-types';

const ATTACK_TECHNIQUE_ID = /^T\d{4}(?:\.\d{3})?$/i;
const PLAN_MAX_ENTITIES = 50;
const PLAN_MAX_REPORT_OBJECTS = 50;
const PLAN_MAX_PIR_ENTITIES = 25;
const VALIDATION_MAX_HUNTS = 20;

// region read
export const findHuntById = (context: AuthContext, user: AuthUser, id: string) => {
  return storeLoadById<BasicStoreEntityHunt>(context, user, id, ENTITY_TYPE_HUNT);
};

export const findHuntsPaginated = (context: AuthContext, user: AuthUser, args: EntityOptions<BasicStoreEntityHunt>) => {
  return pageEntitiesConnection<BasicStoreEntityHunt>(context, user, [ENTITY_TYPE_HUNT], args);
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

export const normalizeHuntInput = async (context: AuthContext, user: AuthUser, input: HuntAddInput): Promise<HuntAddInput> => {
  const normalized: HuntAddInput = {
    ...input,
    hunt_type: input.hunt_type ?? HuntType.Telemetry,
    hunt_source_kind: input.hunt_source_kind ?? HuntSourceKind.Analyst,
    hunt_status: input.hunt_status ?? HuntStatus.Active,
    hunt_schedule: input.hunt_schedule?.trim() || HUNT_SCHEDULE_MANUAL,
    time_window_hours: input.time_window_hours ?? HUNT_DEFAULT_TIME_WINDOW_HOURS,
    escalation_threshold: input.escalation_threshold ?? HUNT_DEFAULT_ESCALATION_THRESHOLD,
    native_queries: normalizeNativeQueries(input.native_queries),
  };
  let techniques = input.huntTechniques ?? [];
  // A Sigma rule tagged with ATT&CK techniques links the hunt to them when no technique is given
  if (techniques.length === 0 && input.sigma_rule) {
    const sigma = validateSigmaRule(input.sigma_rule);
    techniques = sigma.attack_techniques;
  }
  normalized.huntTechniques = techniques.length > 0 ? await resolveTechniqueIds(context, user, techniques) : [];
  return normalized;
};

const refreshNextRunAt = async (context: AuthContext, hunt: BasicStoreEntityHunt) => {
  const nextRunAt = hunt.hunt_status === HUNT_STATUS_ACTIVE ? computeNextRunAt(hunt.hunt_schedule, new Date()) : null;
  await updateHuntRunInformation(context, hunt.internal_id, { next_run_at: nextRunAt ? nextRunAt.toISOString() : null });
};

export const addHunt = async (context: AuthContext, user: AuthUser, input: HuntAddInput) => {
  const huntInput = await normalizeHuntInput(context, user, input);
  const created = await createEntity(context, user, huntInput, ENTITY_TYPE_HUNT) as BasicStoreEntityHunt;
  if (!context.draft_context) {
    await refreshNextRunAt(context, created);
  }
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};

/**
 * Draft-first creation used by agents: a draft workspace is created and the hunt is created inside it, the
 * existing draft approval workflow validates it into the knowledge graph.
 */
export const addHuntProposal = async (context: AuthContext, user: AuthUser, input: HuntAddInput, draftName?: string | null) => {
  const draft = await addDraftWorkspace(context, user, {
    name: (draftName?.trim() || `Hunt proposal - ${input.name}`).substring(0, 250),
    description: input.hypothesis ? `Proposed hunt hypothesis: ${input.hypothesis}` : undefined,
  });
  const draftContext: AuthContext = { ...context, draft_context: draft.id };
  const hunt = await addHunt(draftContext, user, { ...input, hunt_source_kind: input.hunt_source_kind ?? HuntSourceKind.Agent });
  return { draft_id: draft.id, hunt };
};

export const huntDelete = async (context: AuthContext, user: AuthUser, huntId: string) => {
  // Runs are kept so that a hunt restored from the trash keeps its history, the run retention purges them
  await deleteElementById(context, user, huntId, ENTITY_TYPE_HUNT);
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
  const normalizedInput = input.map((editInput) => (editInput.key === 'native_queries'
    ? { ...editInput, value: normalizeNativeQueries(editInput.value) }
    : editInput));
  const updated = await stixDomainObjectEditField(context, user, huntId, normalizedInput, opts) as BasicStoreEntityHunt;
  if (!context.draft_context && input.some((editInput) => ['hunt_schedule', 'hunt_status'].includes(editInput.key))) {
    await refreshNextRunAt(context, updated);
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

export const planHunt = async (context: AuthContext, user: AuthUser, input: HuntPlanInput) => {
  await checkEnterpriseEdition(context);
  if (input.entity_ids.length === 0 || input.entity_ids.length > PLAN_MAX_ENTITIES) {
    throw FunctionalError(`A hunt is planned from 1 to ${PLAN_MAX_ENTITIES} entities`);
  }
  const knowledge = await findByIds<BasicStoreEntity & Record<string, any>>(context, user, input.entity_ids);
  const foundIds = new Set(knowledge.map((element) => element.internal_id));
  const entities = [...knowledge];
  // PIR: the most relevant flagged threats of the PIR are planned for
  const pirIds = input.entity_ids.filter((id) => !foundIds.has(id));
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
  // Reports: the threats, techniques and indicators they contain
  const reports = entities.filter((entity) => entity.entity_type === ENTITY_TYPE_CONTAINER_REPORT);
  for (let index = 0; index < reports.length; index += 1) {
    const objectIds = ((reports[index][RELATION_OBJECT] ?? []) as string[]).slice(0, PLAN_MAX_REPORT_OBJECTS);
    if (objectIds.length > 0) {
      entities.push(...await findByIds<BasicStoreEntity & Record<string, any>>(context, user, objectIds));
    }
  }
  const unique = Array.from(new Map(entities.map((entity) => [entity.internal_id, entity])).values());
  const threats = unique.filter((entity) => HUNT_TARGET_TYPES.includes(entity.entity_type));
  const techniques = unique.filter((entity) => entity.entity_type === ENTITY_TYPE_ATTACK_PATTERN);
  const indicators = unique.filter((entity) => entity.entity_type === ENTITY_TYPE_INDICATOR);
  if (threats.length + techniques.length + indicators.length === 0) {
    throw FunctionalError('No threat, technique or indicator to plan a hunt for');
  }
  const connectors = await findHuntConnectors(context, true);
  const requestedPlatforms = new Set(input.security_platform_ids ?? []);
  const platformIds = connectors
    .map((connector) => connector.security_platform_id)
    .filter((id): id is string => !!id && (requestedPlatforms.size === 0 || requestedPlatforms.has(id)));
  const platforms = platformIds.length > 0
    ? await findByIds<BasicStoreEntitySecurityPlatform>(context, user, platformIds, { type: ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM })
    : [];
  const payload = {
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
    benign_patterns: input.benign_patterns ?? [],
    constraints: { max_time_window_hours: 720, max_escalation_threshold: 10000 },
  };
  const jwtUser = await resolveAgentJwtUser(user.id);
  const { answer } = await callHuntAgent(HUNT_PLANNER_INTENT, jwtUser, payload, input.agent_slug);
  const spec = validateHuntPlanSpec(answer, threats.map((threat) => threat.internal_id));
  addHuntPlanCount();
  // The hunt inherits the markings of the knowledge it was planned from
  const markingIds = Array.from(new Set(unique.flatMap((entity) => (entity[RELATION_OBJECT_MARKING] ?? []) as string[])));
  const huntInput: HuntAddInput = {
    name: spec.name,
    description: [spec.description, spec.rationale ? `Rationale: ${spec.rationale}` : ''].filter((part) => part.length > 0).join('\n\n'),
    hypothesis: spec.hypothesis,
    hunt_type: spec.hunt_type === HuntType.Infrastructure ? HuntType.Infrastructure : HuntType.Telemetry,
    hunt_status: HuntStatus.Active,
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
 * inject, hunt and platform). Completed runs write coverage_information hunt_detected on the security coverage.
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
    securityCoverageId = coverage?.internal_id ?? null;
  }
  const hunts = await fullEntitiesList<BasicStoreEntityHunt>(context, user, [ENTITY_TYPE_HUNT], {
    filters: {
      mode: FilterMode.And,
      filters: [
        { key: ['hunt_status'], values: [HUNT_STATUS_ACTIVE] },
        { key: [RELATION_HUNT_TECHNIQUES], values: [technique.internal_id] },
      ],
      filterGroups: [],
    },
  });
  const existingRuns = await fullEntitiesList<BasicStoreEntityHuntRun>(context, HUNT_MANAGER_USER, [ENTITY_TYPE_HUNT_RUN], {
    filters: {
      mode: FilterMode.And,
      filters: [
        { key: ['aev_inject_id'], values: [input.inject_id] },
        { key: ['security_platform_id'], values: [platform.internal_id] },
        { key: ['hunt_run_trigger'], values: [HUNT_RUN_TRIGGER_EMULATION] },
      ],
      filterGroups: [],
    },
    noFiltersChecking: true,
  });
  const runs: BasicStoreEntityHuntRun[] = [];
  const candidateHunts = hunts.slice(0, VALIDATION_MAX_HUNTS);
  for (let index = 0; index < candidateHunts.length; index += 1) {
    const hunt = candidateHunts[index];
    const existing = existingRuns.filter((run) => run.hunt_id === hunt.internal_id);
    if (existing.length > 0) {
      runs.push(...existing);
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
      runs.push(...created);
    }
  }
  logApp.info('[OPENCTI-MODULE] Hunt validation from emulation', { injectId: input.inject_id, technique: technique.internal_id, platform: platform.internal_id, hunts: candidateHunts.length, runs: runs.length });
  return { hunts_count: candidateHunts.length, runs };
};
// endregion

// region hunt packs
const HUNT_PACK_LOCAL_FIELDS = ['hunt_status', 'hunt_source_kind', 'hunt_schedule', 'hunt_scope', 'trigger_filters', 'hunt_pir_activation'] as const;

export const importHuntPack = async (context: AuthContext, user: AuthUser, file: Promise<FileHandle>) => {
  const { hunts, objects } = await parseHuntPack(file);
  const imported: BasicStoreEntityHunt[] = [];
  const unresolved = new Set<string>();
  for (let index = 0; index < hunts.length; index += 1) {
    const plan = await planHuntPackImport(context, user, hunts[index], objects);
    plan.unresolved.forEach((ref) => unresolved.add(ref));
    if (plan.blocked) {
      logApp.warn('[OPENCTI-MODULE] Hunt pack hunt skipped, its markings are unknown on this platform', { hunt: hunts[index].id });
    } else {
      // A pack updates the definition of a hunt that exists here, never how it runs here (status, origin, schedule)
      const [existing] = await findByIds<BasicStoreEntityHunt>(context, user, [hunts[index].id], { type: ENTITY_TYPE_HUNT });
      const input = { ...plan.input };
      if (existing) {
        HUNT_PACK_LOCAL_FIELDS.forEach((field) => {
          input[field] = existing[field];
        });
      }
      imported.push(await addHunt(context, user, input as unknown as HuntAddInput));
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
  return { hunts: imported, unresolved_refs: Array.from(unresolved) };
};
// endregion
