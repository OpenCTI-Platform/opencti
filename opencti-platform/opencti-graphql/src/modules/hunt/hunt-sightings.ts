import { v5 as uuidv5 } from 'uuid';
import type { AuthContext } from '../../types/user';
import type { BasicStoreEntity, BasicStoreEntityMarkingDefinition, BasicStoreRelation } from '../../types/store';
import { logApp } from '../../config/conf';
import { getEntitiesMapFromCache } from '../../database/cache';
import { createRelation, patchAttribute } from '../../database/middleware';
import { internalLoadById } from '../../database/middleware-loader';
import { OPENCTI_NAMESPACE, STIX_TYPE_SIGHTING } from '../../schema/general';
import { generateStandardId } from '../../schema/identifier';
import { ENTITY_TYPE_ATTACK_PATTERN } from '../../schema/stixDomainObject';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../../schema/stixMetaObject';
import { RELATION_CREATED_BY, RELATION_GRANTED_TO, RELATION_OBJECT_MARKING } from '../../schema/stixRefRelationship';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
import { SYSTEM_USER, HUNT_MANAGER_USER } from '../../utils/access';
import { ENTITY_TYPE_INDICATOR } from '../indicator/indicator-types';
import { findByIds } from './hunt-loaders';
import { isDisclosableByHunt } from './hunt-iocs';
import { type BasicStoreEntityHunt, HUNT_TYPE_INDICATORS, RELATION_HUNT_SOURCES, RELATION_HUNT_TECHNIQUES } from './hunt-types';
import { type BasicStoreEntityHuntRun, HUNT_IOC_VERDICT_SEEN, HUNT_RUN_STATUS_COMPLETED, type HuntIocResult } from './huntRun/huntRun-types';
import { countHuntHitRecords } from './huntHitRecord/huntHitRecord-domain';
import { withHuntLock } from './hunt-lock';
import { truncate } from './hunt-utils';

const HUNT_SIGHTINGS_LOCK = 'hunt_sightings';

// The sighting of the hunt names the hunt it belongs to: one per hunt, sighted object and security platform
export const ATTRIBUTE_HUNT_ID = 'x_opencti_hunt_id';
// The run that updated the sighting last
const ATTRIBUTE_HUNT_RUN_ID_KEY = 'x_opencti_hunt_run_id';

type HuntSighting = BasicStoreRelation & { attribute_count?: number; first_seen?: string; last_seen?: string; x_opencti_hunt_run_id?: string };

/** What the run says of one sighted object: when its hits were seen, how many the run found, which values hold it. */
export interface HuntSightingTarget {
  id: string;
  firstSeen: string;
  lastSeen: string;
  runHits: number;
  // Indicator hunts: the keys of the values of the object, to count its own hits among the known ones
  iocKeys?: string[];
}

export interface HuntSightingsOutcome {
  ids: string[];
  created: number;
  updated: number;
}

const earliest = (dates: (string | null | undefined)[]) => dates.filter((date): date is string => !!date).sort()[0];
const latest = (dates: (string | null | undefined)[]) => dates.filter((date): date is string => !!date).sort().reverse()[0];
const sameIds = (left: string[] = [], right: string[] = []) => left.length === right.length && left.every((id) => right.includes(id));

/**
 * The count of a sighting after a run. A run whose hits are identified recounts the distinct hits known for the object,
 * never below the stored count (forgotten hits stay counted). A run whose hits are not identified adds its hits once:
 * the sighting it last updated already holds them.
 */
export const nextHuntSightingCount = (
  stored: Pick<HuntSighting, 'attribute_count' | 'x_opencti_hunt_run_id'> | null,
  runId: string,
  outcome: { identified: boolean; knownHits: number; runHits: number },
) => {
  const storedCount = stored?.attribute_count ?? 0;
  if (outcome.identified) {
    return Math.max(storedCount, outcome.knownHits, 1);
  }
  if (stored && stored.x_opencti_hunt_run_id === runId) {
    return Math.max(storedCount, 1);
  }
  return Math.max(storedCount + outcome.runHits, 1);
};

// A pasted value comes from no object: the observable its connector created for it is the one sighted
const pastedValueObservableId = (result: HuntIocResult) => {
  try {
    const data = result.observable_type === 'StixFile'
      ? { hashes: { [result.hash_algorithm ?? 'SHA-256']: result.value } }
      : { value: result.value };
    return generateStandardId(result.observable_type, data);
  } catch {
    return null;
  }
};

/**
 * The objects a completed run sights on its security platform. A telemetry hunt sights its techniques and the indicators
 * among its sources, each with every hit of the run; an indicator hunt sights the indicators and observables each seen
 * value comes from (the observable created for a pasted value), each with the hits of its values. Objects more
 * restricted than the hunt are never sighted, as they are never sent to its connector.
 */
export const resolveHuntSightingTargets = async (context: AuthContext, hunt: BasicStoreEntityHunt, run: BasicStoreEntityHuntRun): Promise<HuntSightingTarget[]> => {
  const runFirst = run.first_hit_at ?? run.time_window_start ?? run.completed_at ?? new Date().toISOString();
  const runLast = run.last_hit_at ?? run.time_window_end ?? runFirst;
  if (hunt.hunt_type === HUNT_TYPE_INDICATORS) {
    const byObject = new Map<string, HuntSightingTarget>();
    const seen = (run.ioc_results ?? []).filter((result) => result.verdict === HUNT_IOC_VERDICT_SEEN);
    for (let index = 0; index < seen.length; index += 1) {
      const result = seen[index];
      let ids = result.source_ids ?? [];
      if (ids.length === 0) {
        const standardId = pastedValueObservableId(result);
        const observable = standardId ? await internalLoadById<BasicStoreEntity>(context, HUNT_MANAGER_USER, standardId) : null;
        ids = observable ? [observable.internal_id] : [];
      }
      ids.forEach((id) => {
        const target = byObject.get(id);
        const first = result.first_seen ?? runFirst;
        const last = result.last_seen ?? runLast;
        byObject.set(id, {
          id,
          firstSeen: earliest([target?.firstSeen, first]) as string,
          lastSeen: latest([target?.lastSeen, last]) as string,
          runHits: (target?.runHits ?? 0) + (result.hits_count ?? 0),
          iocKeys: [...(target?.iocKeys ?? []), result.key],
        });
      });
    }
    return Array.from(byObject.values());
  }
  const [techniques, sources, markings] = await Promise.all([
    hunt[RELATION_HUNT_TECHNIQUES]?.length ? findByIds<BasicStoreEntity>(context, SYSTEM_USER, hunt[RELATION_HUNT_TECHNIQUES] ?? [], { type: ENTITY_TYPE_ATTACK_PATTERN }) : [],
    hunt[RELATION_HUNT_SOURCES]?.length ? findByIds<BasicStoreEntity>(context, SYSTEM_USER, hunt[RELATION_HUNT_SOURCES] ?? []) : [],
    getEntitiesMapFromCache<BasicStoreEntityMarkingDefinition>(context, SYSTEM_USER, ENTITY_TYPE_MARKING_DEFINITION),
  ]);
  const disclosable = (element: BasicStoreEntity) => isDisclosableByHunt(hunt, element, markings as Map<string, BasicStoreEntityMarkingDefinition>);
  const sighted = [...techniques, ...sources.filter((source) => source.entity_type === ENTITY_TYPE_INDICATOR)].filter(disclosable);
  return Array.from(new Set(sighted.map((element) => element.internal_id)))
    .map((id) => ({ id, firstSeen: runFirst, lastSeen: runLast, runHits: run.hits_count ?? 0 }));
};

/**
 * The STIX id of the sighting a hunt keeps of an object on a security platform: derived from the three, not from its
 * dates like other sightings, so that it never merges with the sighting of another hunt or of a connector that has
 * the same dates, and stays the same when its dates move.
 */
export const huntSightingStandardId = (huntId: string, sightedId: string, securityPlatformId: string) => {
  return `${STIX_TYPE_SIGHTING}--${uuidv5(`hunt-sighting|${huntId}|${sightedId}|${securityPlatformId}`, OPENCTI_NAMESPACE)}`;
};

const findHuntSighting = async (context: AuthContext, standardId: string) => {
  return internalLoadById<HuntSighting>(context, HUNT_MANAGER_USER, standardId, { type: STIX_SIGHTING_RELATIONSHIP });
};

const sightingDescription = (hunt: BasicStoreEntityHunt, platformName: string, count: number) => {
  return truncate(`Hunt "${hunt.name}" found ${count} distinct hit(s) on ${platformName}. Each run of the hunt updates this sighting: `
    + 'its count holds the distinct hits found so far, its first and last seen dates the first and latest hit.', 2000);
};

const keepHuntSightings = async (
  context: AuthContext,
  hunt: BasicStoreEntityHunt,
  run: BasicStoreEntityHuntRun,
  platform: BasicStoreEntity,
  outcome: HuntSightingsOutcome,
): Promise<HuntSightingsOutcome> => {
  const targets = await resolveHuntSightingTargets(context, hunt, run);
  const identified = run.hits_identified === true;
  // A sighting says what the runs of its hunt found so far: it is restricted like the run that updated it last
  const objectMarking = run[RELATION_OBJECT_MARKING] ?? [];
  const objectOrganization = run[RELATION_GRANTED_TO] ?? [];
  for (let index = 0; index < targets.length; index += 1) {
    const target = targets[index];
    const standardId = huntSightingStandardId(hunt.internal_id, target.id, platform.internal_id);
    const stored = await findHuntSighting(context, standardId);
    const knownHits = identified ? await countHuntHitRecords(context, hunt.internal_id, [platform.internal_id], target.iocKeys) : 0;
    const count = nextHuntSightingCount(stored, run.internal_id, { identified, knownHits, runHits: target.runHits });
    const firstSeen = earliest([stored?.first_seen, target.firstSeen]) as string;
    const lastSeen = latest([stored?.last_seen, target.lastSeen, firstSeen]) as string;
    const description = sightingDescription(hunt, platform.name, count);
    if (stored) {
      const markingsChanged = !sameIds(stored[RELATION_OBJECT_MARKING], objectMarking);
      const organizationsChanged = !sameIds(stored[RELATION_GRANTED_TO], objectOrganization);
      const unchanged = stored.attribute_count === count && stored.first_seen === firstSeen && stored.last_seen === lastSeen
        && stored.x_opencti_hunt_run_id === run.internal_id && !markingsChanged && !organizationsChanged;
      // Its id stays the one derived from the hunt, whatever its dates become
      const element = unchanged ? stored : (await patchAttribute(context, HUNT_MANAGER_USER, stored.internal_id, STIX_SIGHTING_RELATIONSHIP, {
        attribute_count: count,
        first_seen: firstSeen,
        last_seen: lastSeen,
        description,
        [ATTRIBUTE_HUNT_RUN_ID_KEY]: run.internal_id,
        ...(markingsChanged ? { objectMarking } : {}),
        // Organizations can only be written in Enterprise Edition: sent only when they change
        ...(organizationsChanged ? { objectOrganization } : {}),
      }, { impactStandardId: false })).element as unknown as HuntSighting;
      outcome.ids.push(element.standard_id);
      outcome.updated += 1;
    } else {
      const created = await createRelation(context, HUNT_MANAGER_USER, {
        standard_id: standardId,
        relationship_type: STIX_SIGHTING_RELATIONSHIP,
        fromId: target.id,
        toId: platform.internal_id,
        first_seen: firstSeen,
        last_seen: lastSeen,
        attribute_count: count,
        description,
        [ATTRIBUTE_HUNT_ID]: hunt.internal_id,
        [ATTRIBUTE_HUNT_RUN_ID_KEY]: run.internal_id,
        objectMarking,
        objectOrganization,
        ...(hunt[RELATION_CREATED_BY] ? { createdBy: hunt[RELATION_CREATED_BY] } : {}),
      }) as unknown as HuntSighting;
      outcome.ids.push(created.standard_id);
      outcome.created += 1;
    }
  }
  logApp.debug('[OPENCTI-MODULE] Hunt sightings kept', { huntId: hunt.internal_id, runId: run.internal_id, created: outcome.created, updated: outcome.updated });
  return outcome;
};

/**
 * One sighting per hunt, sighted object and security platform, kept by the platform: a completed run with hits creates it
 * or updates it in place (count, first and last seen, the run that updated it last), never a sighting per run. Runs a
 * second time over the same run give the same sightings. The runs of a hunt on a platform keep its sightings one at a
 * time, so two runs finalized together never both create one. Returns the sightings of the run.
 */
export const upsertHuntSightings = async (context: AuthContext, hunt: BasicStoreEntityHunt, run: BasicStoreEntityHuntRun): Promise<HuntSightingsOutcome> => {
  const outcome: HuntSightingsOutcome = { ids: [], created: 0, updated: 0 };
  if (run.hunt_run_status !== HUNT_RUN_STATUS_COMPLETED || !run.security_platform_id || (run.hits_count ?? 0) <= 0) {
    return outcome;
  }
  const platform = await internalLoadById<BasicStoreEntity>(context, HUNT_MANAGER_USER, run.security_platform_id);
  if (!platform) {
    return outcome;
  }
  return withHuntLock(`${HUNT_SIGHTINGS_LOCK}_${hunt.internal_id}_${platform.internal_id}`, () => keepHuntSightings(context, hunt, run, platform, outcome));
};
