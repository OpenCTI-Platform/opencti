import { isIP } from 'node:net';
import type { AuthContext } from '../../types/user';
import type { BasicStoreEntity, BasicStoreEntityMarkingDefinition } from '../../types/store';
import { logApp } from '../../config/conf';
import { getEntitiesMapFromCache } from '../../database/cache';
import { createRelation, patchAttribute } from '../../database/middleware';
import { internalLoadById } from '../../database/middleware-loader';
import { generateStandardId } from '../../schema/identifier';
import { RELATION_RELATED_TO } from '../../schema/stixCoreRelationship';
import { ENTITY_TYPE_ATTACK_PATTERN, ENTITY_TYPE_CONTAINER_OBSERVED_DATA } from '../../schema/stixDomainObject';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../../schema/stixMetaObject';
import { RELATION_CREATED_BY, RELATION_GRANTED_TO, RELATION_OBJECT_MARKING } from '../../schema/stixRefRelationship';
import { HUNT_MANAGER_USER, SYSTEM_USER } from '../../utils/access';
import { ENTITY_TYPE_INDICATOR } from '../indicator/indicator-types';
import { isDisclosableByHunt } from './hunt-iocs';
import { withHuntLock } from './hunt-lock';
import { findByIds } from './hunt-loaders';
import { accumulatedHuntSightingAccess } from './hunt-sightings';
import { type BasicStoreEntityHunt, HUNT_TYPE_INDICATORS, RELATION_HUNT_SOURCES, RELATION_HUNT_TECHNIQUES } from './hunt-types';
import { type BasicStoreEntityHuntRun, HUNT_IOC_VERDICT_SEEN, type HuntHit, type HuntIocResult } from './huntRun/huntRun-types';
import { HUNT_CONFIG, huntRuleKey, huntSigmaRules } from './hunt-utils';

/** An observable a hit names, as the observable creation takes it. */
export interface HuntHitObservable {
  key: string;
  type: string;
  input: Record<string, unknown>;
}

const HASH_ALGORITHMS: Record<number, string> = { 32: 'MD5', 40: 'SHA-1', 64: 'SHA-256' };
const DOMAIN_PATTERN = /^(?=.{1,253}$)(?:[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?\.)+[a-z]{2,63}$/i;
const URL_PATTERN = /^[a-z][a-z\d+.-]*:\/\/\S+$/i;
const MASKED = '[masked';
// A file name reads like a domain and a hash like any hex id: the field the value comes from tells them apart
const COMMAND_LINE_FIELD = /command_?line/i;
const HOSTNAME_FIELD = /hostname/i;
const DOMAIN_FIELD = /domain|dns/i;
const HASH_FIELD = /hash|md5|sha_?(1|256)/i;
// The connector joins the values of a multi-valued field before hashing them
const VALUES_SEPARATOR = ', ';
// The run counts the observed data as its evidence, like the observed data its connector sends
const ATTRIBUTE_HUNT_RUN_ID_KEY = 'x_opencti_hunt_run_id';
const OBSERVED_DATA_LOCK = 'hunt_observed_data';
// The values an indicator hunt looks up whose observable holds them as its value
const VALUE_OBSERVABLE_TYPES = ['IPv4-Addr', 'IPv6-Addr', 'Domain-Name', 'Url', 'Hostname', 'Email-Addr', 'Mac-Addr'];

const usable = (value: string | null | undefined): value is string => {
  return typeof value === 'string' && value.trim().length > 0 && !value.includes(MASKED) && !value.endsWith('...');
};

const addressObservable = (value: string): HuntHitObservable | null => {
  const version = isIP(value);
  if (version === 4) {
    return { key: `IPv4-Addr:${value}`, type: 'IPv4-Addr', input: { IPv4Addr: { value } } };
  }
  return version === 6 ? { key: `IPv6-Addr:${value}`, type: 'IPv6-Addr', input: { IPv6Addr: { value } } } : null;
};

const hostnameObservable = (value: string): HuntHitObservable => ({ key: `Hostname:${value}`, type: 'Hostname', input: { Hostname: { value } } });

const matchedValueObservable = (field: string, value: string): HuntHitObservable | null => {
  const address = addressObservable(value);
  if (address) {
    return address;
  }
  if (URL_PATTERN.test(value)) {
    return { key: `Url:${value}`, type: 'Url', input: { Url: { value } } };
  }
  if (HOSTNAME_FIELD.test(field)) {
    return hostnameObservable(value);
  }
  if (DOMAIN_FIELD.test(field) && DOMAIN_PATTERN.test(value)) {
    const domain = value.toLowerCase();
    return { key: `Domain-Name:${domain}`, type: 'Domain-Name', input: { DomainName: { value: domain } } };
  }
  const hash = value.toLowerCase();
  const algorithm = HASH_FIELD.test(field) && /^[a-f\d]+$/.test(hash) ? HASH_ALGORITHMS[hash.length] : undefined;
  return algorithm ? { key: `StixFile:${hash}`, type: 'StixFile', input: { StixFile: { hashes: [{ algorithm, hash }] } } } : null;
};

/**
 * The observables of one hit: its host and account, and what the fields the hunt logic matched hold (addresses, URLs,
 * host names, domains, file hashes, command lines). Only a complete preview of a matched value names something: a
 * value the platform masked or truncated is skipped. The values an indicator hunt matched are typed by their indicator,
 * not by the field that held them: `withMatched` false leaves them to the observed data of the value.
 */
export const extractHitObservables = (hit: HuntHit, withMatched = true): HuntHitObservable[] => {
  const observables: HuntHitObservable[] = [];
  (withMatched ? hit.matched ?? [] : []).filter((match) => match.value_complete && usable(match.value_preview)).forEach((match) => {
    const value = (match.value_preview as string).trim();
    if (COMMAND_LINE_FIELD.test(match.field)) {
      observables.push({ key: `Process:${value}`, type: 'Process', input: { Process: { command_line: value } } });
      return;
    }
    value.split(VALUES_SEPARATOR).map((part) => part.trim()).forEach((part) => {
      const observable = part.length > 0 ? matchedValueObservable(match.field, part) : null;
      if (observable) {
        observables.push(observable);
      }
    });
  });
  if (usable(hit.host)) {
    observables.push(hostnameObservable(hit.host.trim()));
  }
  if (usable(hit.user)) {
    const value = hit.user.trim();
    observables.push({ key: `User-Account:${value}`, type: 'User-Account', input: { UserAccount: { account_login: value } } });
  }
  const unique = new Map(observables.map((observable) => [observable.key, observable]));
  return Array.from(unique.values());
};

/** The observable of a value an indicator hunt looked up, of the type its indicator pattern gives it. */
export const iocValueObservable = (result: Pick<HuntIocResult, 'observable_type' | 'value' | 'hash_algorithm'>): HuntHitObservable | null => {
  const value = (result.value ?? '').trim();
  if (value.length === 0) {
    return null;
  }
  if (result.observable_type === 'StixFile') {
    const hash = value.toLowerCase();
    const algorithm = result.hash_algorithm ?? HASH_ALGORITHMS[hash.length];
    return algorithm ? { key: `StixFile:${hash}`, type: 'StixFile', input: { StixFile: { hashes: [{ algorithm, hash }] } } } : null;
  }
  if (!VALUE_OBSERVABLE_TYPES.includes(result.observable_type)) {
    return null;
  }
  return { key: `${result.observable_type}:${value}`, type: result.observable_type, input: { [result.observable_type.replace(/-/g, '')]: { value } } };
};

/** What a value (or a rule) matched on its victims over every hit of a run: the observations of one observed data. */
export interface HuntObservedGroup {
  key: string;
  hosts: string[];
  hitsCount: number;
  // Hits no run found before on the platform; null when the hits are not identified
  newHitsCount: number | null;
  firstSeen: string;
  lastSeen: string;
}

/**
 * The observation groups of a completed run, the most observed first, at most `maxItems`: those its connector reported
 * over every hit, one per value (or rule) and victim. A connector that reports none gives one group per value seen, on
 * the hosts it names, or one group for the whole run of a telemetry hunt; their hits are not identified.
 */
export const huntRunObservedGroups = (
  hunt: Pick<BasicStoreEntityHunt, 'hunt_type' | 'sigma_rule' | 'sigma_rules'>,
  run: BasicStoreEntityHuntRun,
  maxItems = HUNT_CONFIG.hitObservedDataMaxItems,
): HuntObservedGroup[] => {
  const runFirst = run.first_hit_at ?? run.time_window_start ?? run.completed_at ?? new Date().toISOString();
  const runLast = run.last_hit_at ?? run.time_window_end ?? runFirst;
  let groups: HuntObservedGroup[];
  if (Array.isArray(run.observations) && run.observations.length > 0) {
    groups = run.observations.map((observation) => ({
      key: observation.key,
      hosts: observation.host ? [observation.host] : [],
      hitsCount: observation.hits_count,
      newHitsCount: typeof observation.new_hits_count === 'number' ? observation.new_hits_count : null,
      firstSeen: observation.first_seen ?? runFirst,
      lastSeen: observation.last_seen ?? observation.first_seen ?? runLast,
    }));
  } else if (hunt.hunt_type === HUNT_TYPE_INDICATORS) {
    groups = (run.ioc_results ?? []).filter((result) => result.verdict === HUNT_IOC_VERDICT_SEEN && (result.hits_count ?? 0) > 0).map((result) => ({
      key: result.key,
      hosts: (result.hosts ?? []).filter(usable),
      hitsCount: result.hits_count,
      newHitsCount: null,
      firstSeen: result.first_seen ?? runFirst,
      lastSeen: result.last_seen ?? result.first_seen ?? runLast,
    }));
  } else {
    const [firstRule] = huntSigmaRules(hunt);
    groups = (run.hits_count ?? 0) > 0
      ? [{ key: firstRule ? huntRuleKey(firstRule) : '', hosts: [], hitsCount: run.hits_count ?? 0, newHitsCount: null, firstSeen: runFirst, lastSeen: runLast }]
      : [];
  }
  return groups
    .filter((group) => group.hitsCount > 0)
    .sort((a, b) => b.hitsCount - a.hitsCount || a.key.localeCompare(b.key))
    .slice(0, maxItems);
};

/**
 * The number of observations of an observed data after a run. Hits identified add the hits no run found before on the
 * platform; hits not identified cannot be told from those already counted: the count becomes the hits of the run when
 * they are more, never their sum. A new observed data counts every hit of the run.
 */
export const nextHuntObservedCount = (stored: number | null | undefined, group: Pick<HuntObservedGroup, 'hitsCount' | 'newHitsCount'>) => {
  if (stored === null || stored === undefined) {
    return Math.max(group.hitsCount, 1);
  }
  if (group.newHitsCount !== null) {
    return Math.max(stored + group.newHitsCount, 1);
  }
  return Math.max(stored, group.hitsCount, 1);
};

const earliest = (dates: (string | null | undefined)[]) => dates.filter((date): date is string => !!date).sort()[0];
const latest = (dates: (string | null | undefined)[]) => dates.filter((date): date is string => !!date).sort().reverse()[0];

type ObservedData = BasicStoreEntity & { number_observed?: number; first_observed?: string; last_observed?: string; x_opencti_hunt_run_id?: string };

/**
 * The observables the hits of the sample name (commands, accounts, hosts and, for a telemetry hunt, the values the hunt
 * logic matched), and one Observed Data per value (or rule), victim and security platform over every hit of the run: its
 * objects are the observable of the value typed by its indicator (or the indicator of the rule, else the techniques of
 * the hunt), the victim as a System related to its Hostname, and the platform. Its identifier derives from its objects,
 * so every run and every hunt observing the same value on the same victim updates it: its count and dates are written
 * by the platform (nextHuntObservedCount), never summed by an upsert. A finalization replayed changes nothing: the
 * observed data the run updated last is left as it is. A step that fails is logged and skipped. Returns the internal
 * ids of the observed data, and of the observables and systems.
 */
export const createHuntHitObservations = async (context: AuthContext, hunt: BasicStoreEntityHunt, run: BasicStoreEntityHuntRun) => {
  // Loaded on use: the observable, observed data and system domains import the whole schema, the hunt module is part of it
  const [{ addStixCyberObservable }, { addObservedData }, { addSystem }] = await Promise.all([
    import('../../domain/stixCyberObservable'),
    import('../../domain/observedData'),
    import('../../domain/system'),
  ]);
  const access = {
    objectMarking: run[RELATION_OBJECT_MARKING] ?? [],
    objectOrganization: run[RELATION_GRANTED_TO] ?? [],
    ...(hunt[RELATION_CREATED_BY] ? { createdBy: hunt[RELATION_CREATED_BY] } : {}),
  };
  const isIndicatorHunt = hunt.hunt_type === HUNT_TYPE_INDICATORS;
  const known = new Map<string, BasicStoreEntity>();
  const ensure = async (key: string, create: () => Promise<unknown>) => {
    let element = known.get(key);
    if (!element) {
      element = await create() as BasicStoreEntity;
      known.set(key, element);
    }
    return element;
  };
  const ensureObservable = (observable: HuntHitObservable) => ensure(observable.key, () => addStixCyberObservable(context, HUNT_MANAGER_USER, {
    type: observable.type,
    ...observable.input,
    ...access,
  }));
  const ensureVictim = async (host: string) => {
    const hostname = await ensureObservable(hostnameObservable(host));
    const system = await ensure(`System:${host}`, () => addSystem(context, HUNT_MANAGER_USER, { name: host, ...access }));
    if (!known.has(`System-Hostname:${host}`)) {
      known.set(`System-Hostname:${host}`, system);
      try {
        await createRelation(context, HUNT_MANAGER_USER, {
          fromId: system.internal_id,
          toId: hostname.internal_id,
          relationship_type: RELATION_RELATED_TO,
          objectMarking: access.objectMarking,
        });
      } catch (error) {
        logApp.warn('[OPENCTI-MODULE] Hunt victim system could not be related to its hostname', { cause: error, runId: run.internal_id });
      }
    }
    return system;
  };
  const evidenceIds = new Set<string>();
  const sample = run.hits_sample ?? [];
  for (let index = 0; index < sample.length; index += 1) {
    try {
      const observables = extractHitObservables(sample[index], !isIndicatorHunt);
      for (let position = 0; position < observables.length; position += 1) {
        evidenceIds.add((await ensureObservable(observables[position])).internal_id);
      }
    } catch (error) {
      logApp.warn('[OPENCTI-MODULE] Hunt hit observables could not be created', { cause: error, runId: run.internal_id, hit: index });
    }
  }
  const groups = huntRunObservedGroups(hunt, run);
  const observedDataIds = new Set<string>();
  if (groups.length === 0) {
    return { observedDataIds: [], observableIds: Array.from(evidenceIds) };
  }
  const platform = run.security_platform_id ? await internalLoadById<BasicStoreEntity>(context, HUNT_MANAGER_USER, run.security_platform_id) : null;
  // A telemetry run observes the indicator of each rule it ran, else the techniques of its hunt
  const ruleObjects = new Map<string, BasicStoreEntity[]>();
  let techniques: BasicStoreEntity[] = [];
  if (!isIndicatorHunt) {
    const sourceIds = hunt[RELATION_HUNT_SOURCES] ?? [];
    const [sources, huntTechniques, markings] = await Promise.all([
      sourceIds.length > 0 ? findByIds<BasicStoreEntity & { pattern?: string; pattern_type?: string }>(context, SYSTEM_USER, sourceIds, { type: ENTITY_TYPE_INDICATOR }) : [],
      hunt[RELATION_HUNT_TECHNIQUES]?.length ? findByIds<BasicStoreEntity>(context, SYSTEM_USER, hunt[RELATION_HUNT_TECHNIQUES] ?? [], { type: ENTITY_TYPE_ATTACK_PATTERN }) : [],
      getEntitiesMapFromCache<BasicStoreEntityMarkingDefinition>(context, SYSTEM_USER, ENTITY_TYPE_MARKING_DEFINITION),
    ]);
    const disclosable = (element: BasicStoreEntity) => isDisclosableByHunt(hunt, element, markings as Map<string, BasicStoreEntityMarkingDefinition>);
    sources.filter((source) => source.pattern_type === 'sigma' && typeof source.pattern === 'string' && disclosable(source)).forEach((source) => {
      const key = huntRuleKey(source.pattern as string);
      ruleObjects.set(key, [...(ruleObjects.get(key) ?? []), source]);
    });
    techniques = huntTechniques.filter(disclosable);
  }
  const iocResults = new Map((run.ioc_results ?? []).map((result) => [result.key, result]));
  const observe = async () => {
    for (let index = 0; index < groups.length; index += 1) {
      const group = groups[index];
      try {
        const subjects: BasicStoreEntity[] = [];
        if (isIndicatorHunt) {
          const result = iocResults.get(group.key);
          const observable = result ? iocValueObservable(result) : null;
          if (observable) {
            subjects.push(await ensureObservable(observable));
          } else if (result && result.source_ids.length > 0) {
            subjects.push(...await findByIds<BasicStoreEntity>(context, SYSTEM_USER, result.source_ids));
          }
        } else {
          subjects.push(...(ruleObjects.get(group.key) ?? techniques));
        }
        const victims: BasicStoreEntity[] = [];
        for (let position = 0; position < group.hosts.length; position += 1) {
          victims.push(await ensureVictim(group.hosts[position]));
        }
        victims.forEach((victim) => evidenceIds.add(victim.internal_id));
        subjects.forEach((subject) => evidenceIds.add(subject.internal_id));
        // Without intel to name, the observed data holds what the hits were seen on
        if (subjects.length === 0 && victims.length === 0) {
          continue;
        }
        const objects = [...subjects, ...victims, ...(platform ? [platform] : [])];
        const objectIds = Array.from(new Set(objects.map((object) => object.internal_id)));
        const standardId = generateStandardId(ENTITY_TYPE_CONTAINER_OBSERVED_DATA, { objects: objects.map((object) => ({ standard_id: object.standard_id })) });
        const stored = await internalLoadById<ObservedData>(context, HUNT_MANAGER_USER, standardId, { type: ENTITY_TYPE_CONTAINER_OBSERVED_DATA });
        if (stored && stored.x_opencti_hunt_run_id === run.internal_id) {
          observedDataIds.add(stored.internal_id);
          continue;
        }
        const firstObserved = earliest([stored?.first_observed, group.firstSeen]) as string;
        const lastObserved = latest([stored?.last_observed, group.lastSeen, firstObserved]) as string;
        const numberObserved = nextHuntObservedCount(stored ? stored.number_observed ?? 0 : null, group);
        if (stored) {
          const { objectMarking, objectOrganization } = await accumulatedHuntSightingAccess(context, stored as never, access.objectMarking, access.objectOrganization);
          await patchAttribute(context, HUNT_MANAGER_USER, stored.internal_id, ENTITY_TYPE_CONTAINER_OBSERVED_DATA, {
            number_observed: numberObserved,
            first_observed: firstObserved,
            last_observed: lastObserved,
            [ATTRIBUTE_HUNT_RUN_ID_KEY]: run.internal_id,
            objectMarking,
            objectOrganization,
          });
          observedDataIds.add(stored.internal_id);
        } else {
          const created = await addObservedData(context, HUNT_MANAGER_USER, {
            first_observed: firstObserved,
            last_observed: lastObserved,
            number_observed: numberObserved,
            objects: objectIds,
            [ATTRIBUTE_HUNT_RUN_ID_KEY]: run.internal_id,
            ...access,
          }) as BasicStoreEntity;
          observedDataIds.add(created.internal_id);
        }
      } catch (error) {
        logApp.warn('[OPENCTI-MODULE] Hunt observed data could not be kept', { cause: error, runId: run.internal_id, group: index });
      }
    }
  };
  await withHuntLock(`${OBSERVED_DATA_LOCK}_${run.security_platform_id ?? 'internet'}`, observe);
  return { observedDataIds: Array.from(observedDataIds), observableIds: Array.from(evidenceIds) };
};
