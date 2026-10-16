import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreEntity, BasicStoreRelation } from '../../types/store';
import { pageRegardingEntitiesConnection, storeLoadById, topRelationsList } from '../../database/middleware-loader';
import { ABSTRACT_STIX_CORE_OBJECT } from '../../schema/general';
import { RELATION_OBJECT } from '../../schema/stixRefRelationship';
import { RELATION_ATTRIBUTED_TO, RELATION_INDICATES, RELATION_USES } from '../../schema/stixCoreRelationship';
import {
  ENTITY_TYPE_ATTACK_PATTERN,
  ENTITY_TYPE_CAMPAIGN,
  ENTITY_TYPE_INTRUSION_SET,
  ENTITY_TYPE_MALWARE,
  ENTITY_TYPE_THREAT_ACTOR_GROUP,
  ENTITY_TYPE_TOOL,
} from '../../schema/stixDomainObject';
import { ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL } from '../threatActorIndividual/threatActorIndividual-types';
import { ENTITY_TYPE_INDICATOR } from '../indicator/indicator-types';
import { findByIds } from './hunt-loaders';
import { HUNT_IOC_CONTAINER_TYPES, HUNT_IOC_OBSERVABLE_TYPES, HUNT_IOC_SUBJECT_TYPES, HUNT_TARGET_TYPES } from './hunt-entity-types';
import { type IocElement, iocElementName, iocValuesOfElement, listContainedIocElements, listRelatedElements, listSubjectIocElements } from './hunt-iocs';
import { HUNT_CONFIG, HUNT_MAX_SIGMA_RULES } from './hunt-utils';
import { type HuntAddInput, HuntDerivedSourceRelation, HuntType, OrderingMode, PirRelationshipOrdering } from '../../generated/graphql';
import { ENTITY_TYPE_PIR } from '../pir/pir-types';
import { findPirRelationPaginated } from '../pir/pir-domain';

/** Pattern types of the indicators a detection-rule hunt runs: the Sigma rule, or a native query of its language. */
export const HUNT_RULE_PATTERN_TYPES = ['sigma', 'spl', 'kql', 'eql', 'esql'];

// The malware and tools a threat uses, and the threats attributed to it, each list capped
export const HUNT_MAX_RELATED_SOURCES = 25;
const MAX_TECHNIQUES = 200;
const MAX_RULE_RELATIONS = 500;
const MAX_TARGETS = 100;
// The threats of a PIR a hunt started from it follows: the most relevant ones it flags, as a hunt planned from the PIR
const MAX_PIR_THREATS = 25;

const THREAT_ATTRIBUTION_TYPES: Record<string, string[]> = {
  [ENTITY_TYPE_INTRUSION_SET]: [ENTITY_TYPE_CAMPAIGN],
  [ENTITY_TYPE_THREAT_ACTOR_GROUP]: [ENTITY_TYPE_INTRUSION_SET, ENTITY_TYPE_CAMPAIGN],
  [ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL]: [ENTITY_TYPE_INTRUSION_SET, ENTITY_TYPE_CAMPAIGN],
};
const THREAT_ARSENAL_TYPES = [ENTITY_TYPE_MALWARE, ENTITY_TYPE_TOOL];

export interface HuntDerivedEntity {
  id: string;
  entity_type: string;
  name: string;
}

export interface HuntDerivedSource extends HuntDerivedEntity {
  relation: HuntDerivedSourceRelation;
}

export interface HuntDerivedElement extends HuntDerivedEntity {
  value_types: string[];
  source_ids: string[];
}

export interface HuntDerivedTechnique extends HuntDerivedEntity {
  x_mitre_id: string | null;
}

export interface HuntDerivedRule extends HuntDerivedEntity {
  pattern_type: string;
  pattern: string;
  technique_ids: string[];
  pinned: boolean;
}

export interface HuntDerivedContent {
  entity: HuntDerivedSource;
  suggested_type: HuntType | null;
  sources: HuntDerivedSource[];
  targets: HuntDerivedSource[];
  elements: HuntDerivedElement[];
  elements_truncated: boolean;
  unsupported_count: number;
  techniques: HuntDerivedTechnique[];
  rules: HuntDerivedRule[];
  rules_truncated: boolean;
}

const toDerived = (entity: BasicStoreEntity & Record<string, any>): HuntDerivedEntity => ({
  id: entity.internal_id,
  entity_type: entity.entity_type,
  name: iocElementName(entity),
});

const regarding = async (context: AuthContext, user: AuthUser, id: string, relationType: string, types: string[], reverse: boolean, first: number) => {
  const connection = await pageRegardingEntitiesConnection<IocElement>(context, user, id, relationType, types, reverse, { first });
  return connection.edges.map((edge) => edge.node);
};

const isRule = (element: IocElement) => element.entity_type === ENTITY_TYPE_INDICATOR
  && HUNT_RULE_PATTERN_TYPES.includes(String(element.pattern_type ?? '').toLowerCase())
  && typeof element.pattern === 'string' && element.pattern.trim().length > 0;

const toDerivedRule = (indicator: IocElement, pinned: boolean): HuntDerivedRule => ({
  ...toDerived(indicator),
  pattern_type: String(indicator.pattern_type).toLowerCase(),
  pattern: indicator.pattern,
  technique_ids: [],
  pinned,
});

/**
 * The entities an indicator hunt started from the entity takes its values from: the entity itself and, for a threat,
 * the malware and tools it uses and the intrusion sets and campaigns attributed to it.
 */
const deriveSources = async (context: AuthContext, user: AuthUser, entity: IocElement): Promise<HuntDerivedSource[]> => {
  const self: HuntDerivedSource = { ...toDerived(entity), relation: HuntDerivedSourceRelation.Self };
  if (!HUNT_TARGET_TYPES.includes(entity.entity_type) || entity.entity_type === ENTITY_TYPE_MALWARE) {
    return [self];
  }
  const attributionTypes = THREAT_ATTRIBUTION_TYPES[entity.entity_type] ?? [];
  const [arsenal, attributed] = await Promise.all([
    regarding(context, user, entity.internal_id, RELATION_USES, THREAT_ARSENAL_TYPES, false, HUNT_MAX_RELATED_SOURCES),
    attributionTypes.length > 0 ? regarding(context, user, entity.internal_id, RELATION_ATTRIBUTED_TO, attributionTypes, true, HUNT_MAX_RELATED_SOURCES) : Promise.resolve([]),
  ]);
  const related = [
    ...arsenal.map((source): HuntDerivedSource => ({ ...toDerived(source), relation: HuntDerivedSourceRelation.Uses })),
    ...attributed.map((source): HuntDerivedSource => ({ ...toDerived(source), relation: HuntDerivedSourceRelation.Attributed })),
  ];
  return Array.from(new Map([self, ...related].map((source) => [source.id, source])).values());
};

/** The techniques the entity points to: used by the threat (or its sources), contained, indicated, or the technique itself. */
const deriveTechniques = async (context: AuthContext, user: AuthUser, entity: IocElement, sources: HuntDerivedSource[]): Promise<IocElement[]> => {
  if (entity.entity_type === ENTITY_TYPE_ATTACK_PATTERN) {
    return [entity];
  }
  if (HUNT_IOC_CONTAINER_TYPES.includes(entity.entity_type)) {
    return regarding(context, user, entity.internal_id, RELATION_OBJECT, [ENTITY_TYPE_ATTACK_PATTERN], false, MAX_TECHNIQUES);
  }
  if (entity.entity_type === ENTITY_TYPE_INDICATOR) {
    return listRelatedElements(context, user, RELATION_INDICATES, { fromId: entity.internal_id }, [ENTITY_TYPE_ATTACK_PATTERN], MAX_TECHNIQUES);
  }
  const subjects = sources.filter((source) => HUNT_IOC_SUBJECT_TYPES.includes(source.entity_type));
  const used = await Promise.all(subjects.map((source) => regarding(context, user, source.id, RELATION_USES, [ENTITY_TYPE_ATTACK_PATTERN], false, MAX_TECHNIQUES)));
  return used.flat();
};

/** The threats a hunt started from the entity targets. */
const deriveTargets = async (context: AuthContext, user: AuthUser, entity: IocElement, sources: HuntDerivedSource[]): Promise<HuntDerivedSource[]> => {
  if (HUNT_IOC_CONTAINER_TYPES.includes(entity.entity_type)) {
    const contained = await regarding(context, user, entity.internal_id, RELATION_OBJECT, HUNT_TARGET_TYPES, false, MAX_TARGETS);
    return contained.map((target) => ({ ...toDerived(target), relation: HuntDerivedSourceRelation.Self }));
  }
  if (entity.entity_type === ENTITY_TYPE_INDICATOR) {
    const indicated = await listRelatedElements(context, user, RELATION_INDICATES, { fromId: entity.internal_id }, HUNT_TARGET_TYPES, MAX_TARGETS);
    return indicated.map((target) => ({ ...toDerived(target), relation: HuntDerivedSourceRelation.Self }));
  }
  return sources.filter((source) => HUNT_TARGET_TYPES.includes(source.entity_type));
};

/** The indicators and observables of the entity and of its sources, read with the access of the user. */
const deriveElements = async (context: AuthContext, user: AuthUser, entity: IocElement, sources: HuntDerivedSource[]) => {
  const max = HUNT_CONFIG.maxIocsPerRun;
  let truncated = false;
  const found: { element: IocElement; sourceId: string }[] = [];
  if (entity.entity_type === ENTITY_TYPE_INDICATOR || HUNT_IOC_OBSERVABLE_TYPES.includes(entity.entity_type)) {
    found.push({ element: entity, sourceId: entity.internal_id });
  }
  for (let index = 0; index < sources.length; index += 1) {
    const source = sources[index];
    let expanded: IocElement[] = [];
    if (HUNT_IOC_CONTAINER_TYPES.includes(source.entity_type)) {
      expanded = await listContainedIocElements(context, user, source.id, max + 1);
    } else if (HUNT_IOC_SUBJECT_TYPES.includes(source.entity_type)) {
      expanded = await listSubjectIocElements(context, user, source.id, max + 1);
    }
    truncated = truncated || expanded.length > max;
    expanded.filter((element) => element.revoked !== true).forEach((element) => found.push({ element, sourceId: source.id }));
  }
  return { found, truncated };
};

/**
 * The entity a hunt starts from: a STIX core object, or a PIR, whose most relevant flagged threats (by PIR score) the
 * hunt then follows, read with the access of the user.
 */
const loadDerivationEntity = async (context: AuthContext, user: AuthUser, entityId: string) => {
  const entity = await storeLoadById<IocElement>(context, user, entityId, ABSTRACT_STIX_CORE_OBJECT);
  if (entity) {
    return { entity, flaggedThreats: null };
  }
  const pir = await storeLoadById<IocElement>(context, user, entityId, ENTITY_TYPE_PIR).catch(() => null);
  if (!pir) {
    return null;
  }
  const flagged = await findPirRelationPaginated(context, user, {
    pirId: pir.internal_id,
    first: MAX_PIR_THREATS,
    orderBy: PirRelationshipOrdering.PirScore,
    orderMode: OrderingMode.Desc,
  });
  const threatIds: string[] = flagged.edges.map((edge: { node: { fromId: string } }) => edge.node.fromId);
  const threats = threatIds.length > 0 ? await findByIds<IocElement>(context, user, threatIds) : [];
  return { entity: pir, flaggedThreats: threats.filter((threat) => HUNT_TARGET_TYPES.includes(threat.entity_type)) };
};

/** The sources of the threats a PIR flags: each threat, the malware and tools it uses and the threats attributed to it. */
const deriveFlaggedSources = async (context: AuthContext, user: AuthUser, threats: IocElement[]): Promise<HuntDerivedSource[]> => {
  const perThreat = await Promise.all(threats.map((threat) => deriveSources(context, user, threat)));
  const sources = perThreat.flat().map((source) => (threats.some((threat) => threat.internal_id === source.id)
    ? { ...source, relation: HuntDerivedSourceRelation.Flagged }
    : source));
  return Array.from(new Map(sources.map((source) => [source.id, source])).values());
};

/**
 * What a hunt started from an entity looks for, as "Hunt this" proposes it: the indicators and observables an
 * indicator hunt looks up (those of the entity, of the malware and tools a threat uses and of the threats attributed
 * to it, contained in a report, a grouping or a case, or indicating an incident), the techniques the entity points to,
 * and the detection rules a detection-rule hunt can run: the Sigma, SPL, KQL, EQL and ES|QL indicators of the entity,
 * or indicating its techniques, as the defense matrix links detection rules to techniques. Everything is read with
 * the access of the user: what he cannot see is never derived.
 */
export const deriveHuntContent = async (context: AuthContext, user: AuthUser, entityId: string): Promise<HuntDerivedContent | null> => {
  const loaded = await loadDerivationEntity(context, user, entityId);
  if (!loaded) {
    return null;
  }
  const { entity, flaggedThreats } = loaded;
  const sources = flaggedThreats ? await deriveFlaggedSources(context, user, flaggedThreats) : await deriveSources(context, user, entity);
  const [{ found, truncated }, techniqueEntities, targets] = await Promise.all([
    deriveElements(context, user, entity, sources),
    deriveTechniques(context, user, entity, sources),
    deriveTargets(context, user, entity, sources),
  ]);
  const elements = new Map<string, HuntDerivedElement>();
  const rules = new Map<string, HuntDerivedRule>();
  const seen = new Set<string>();
  let unsupported = 0;
  found.forEach(({ element, sourceId }) => {
    const existing = elements.get(element.internal_id);
    if (existing && !existing.source_ids.includes(sourceId)) {
      existing.source_ids.push(sourceId);
    }
    if (seen.has(element.internal_id)) {
      return;
    }
    seen.add(element.internal_id);
    const values = iocValuesOfElement(element);
    if (values.length > 0) {
      elements.set(element.internal_id, { ...toDerived(element), value_types: Array.from(new Set(values.map((value) => value.observable_type))), source_ids: [sourceId] });
    } else if (isRule(element)) {
      rules.set(element.internal_id, toDerivedRule(element, element.internal_id === entity.internal_id));
    } else {
      unsupported += 1;
    }
  });
  const techniques = Array.from(new Map(techniqueEntities.map((technique) => [technique.internal_id, technique])).values()).slice(0, MAX_TECHNIQUES);
  const techniqueIds = techniques.map((technique) => technique.internal_id);
  if (techniqueIds.length > 0) {
    const relations = await topRelationsList<any>(context, user, RELATION_INDICATES, {
      toId: techniqueIds,
      fromTypes: [ENTITY_TYPE_INDICATOR],
      first: MAX_RULE_RELATIONS,
    }) as BasicStoreRelation[];
    const indicators = await findByIds<IocElement>(context, user, Array.from(new Set(relations.map((relation) => relation.fromId))), { type: ENTITY_TYPE_INDICATOR });
    const byId = new Map(indicators.map((indicator) => [indicator.internal_id, indicator]));
    relations.forEach((relation) => {
      const indicator = byId.get(relation.fromId);
      if (!indicator || indicator.revoked === true || !isRule(indicator)) {
        return;
      }
      const rule = rules.get(indicator.internal_id) ?? toDerivedRule(indicator, indicator.internal_id === entity.internal_id);
      if (!rule.technique_ids.includes(relation.toId)) rule.technique_ids.push(relation.toId);
      rules.set(indicator.internal_id, rule);
    });
  }
  // The rule the hunt starts from comes first and is never left out; the others by the techniques they cover
  const allRules = Array.from(rules.values());
  const pinnedRules = allRules.filter((rule) => rule.pinned);
  const sortedRules = [
    ...pinnedRules,
    ...allRules
      .filter((rule) => !rule.pinned)
      .sort((a, b) => b.technique_ids.length - a.technique_ids.length || a.name.localeCompare(b.name))
      .slice(0, Math.max(0, HUNT_MAX_SIGMA_RULES - pinnedRules.length)),
  ];
  const derivedElements = Array.from(elements.values());
  let suggestedType: HuntType | null = null;
  if (derivedElements.length > 0) {
    suggestedType = HuntType.Indicators;
  } else if (sortedRules.length > 0) {
    suggestedType = HuntType.Telemetry;
  }
  return {
    entity: { ...toDerived(entity), relation: HuntDerivedSourceRelation.Self },
    suggested_type: suggestedType,
    sources: sources.filter((source) => HUNT_IOC_CONTAINER_TYPES.includes(source.entity_type) || HUNT_IOC_SUBJECT_TYPES.includes(source.entity_type)),
    targets: Array.from(new Map(targets.map((target) => [target.id, target])).values()),
    elements: derivedElements.slice(0, HUNT_CONFIG.maxIocsPerRun),
    elements_truncated: truncated || derivedElements.length > HUNT_CONFIG.maxIocsPerRun,
    unsupported_count: unsupported,
    techniques: techniques.map((technique) => ({ ...toDerived(technique), x_mitre_id: technique.x_mitre_id ?? null })),
    rules: sortedRules,
    rules_truncated: allRules.length > sortedRules.length,
  };
};

// Platform a native query written in the pattern language of a detection rule runs on
const RULE_PATTERN_PLATFORMS: Record<string, string> = { spl: 'splunk', kql: 'microsoft-sentinel', eql: 'elastic-security', esql: 'elastic-security' };
const DERIVED_TECHNIQUES_MAX = 50;

/** The name of a hunt started from an entity, as "Hunt this" proposes it: hunts are identified by their name. */
export const derivedHuntName = (entityName: string) => `Hunt - ${entityName}`.substring(0, 250);

/**
 * The hunt derived content turns into, as "Hunt this" proposes it with every suggestion kept: an indicator hunt over
 * the sources when indicators were found, else a detection-rule hunt running every Sigma rule (a native query of the
 * first rule written in another language when there is no Sigma rule). Null when nothing can be hunted.
 */
export const derivedHuntInput = (derived: HuntDerivedContent): HuntAddInput | null => {
  const name = derivedHuntName(derived.entity.name);
  const huntTargets = derived.targets.map((target) => target.id);
  const techniqueIds = derived.techniques.map((technique) => technique.id).slice(0, DERIVED_TECHNIQUES_MAX);
  if (derived.suggested_type === HuntType.Indicators) {
    const ownElements = derived.elements.filter((element) => element.id === derived.entity.id).map((element) => element.id);
    return {
      name,
      hunt_type: HuntType.Indicators,
      huntTargets,
      huntTechniques: techniqueIds,
      huntSources: Array.from(new Set([...derived.sources.map((source) => source.id), ...ownElements])),
    };
  }
  const sigmaRules = derived.rules.filter((rule) => rule.pattern_type === 'sigma');
  const nativeRule = derived.rules.find((rule) => RULE_PATTERN_PLATFORMS[rule.pattern_type]);
  if (sigmaRules.length === 0 && !nativeRule) {
    return null;
  }
  const native = nativeRule as HuntDerivedRule;
  const rules = sigmaRules.length > 0 ? sigmaRules : [native];
  const ruleTechniques = rules.flatMap((rule) => rule.technique_ids);
  return {
    name,
    hunt_type: HuntType.Telemetry,
    huntTargets,
    huntTechniques: Array.from(new Set([...ruleTechniques, ...techniqueIds])).slice(0, DERIVED_TECHNIQUES_MAX),
    huntSources: rules.map((rule) => rule.id),
    ...(sigmaRules.length > 0
      ? { sigma_rules: sigmaRules.map((rule) => rule.pattern) }
      : { native_queries: [{ platform: RULE_PATTERN_PLATFORMS[native.pattern_type], language: native.pattern_type, query: native.pattern }] }),
  };
};
