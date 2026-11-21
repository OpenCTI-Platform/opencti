import type { AuthContext, AuthUser } from '../../../../types/user';
import type { BasicStoreObject, BasicStoreRelation } from '../../../../types/store';
import { fullRelationsList, internalFindByIds } from '../../../../database/middleware-loader';
import { RELATION_EXTERNAL_REFERENCE } from '../../../../schema/stixRefRelationship';
import { ENTITY_TYPE_EXTERNAL_REFERENCE } from '../../../../schema/stixMetaObject';
import {
  ENTITY_TYPE_ATTACK_PATTERN,
  ENTITY_TYPE_CAMPAIGN,
  ENTITY_TYPE_CONTAINER_REPORT,
  ENTITY_TYPE_IDENTITY_SYSTEM,
  ENTITY_TYPE_INCIDENT,
  ENTITY_TYPE_INTRUSION_SET,
  ENTITY_TYPE_MALWARE,
  ENTITY_TYPE_THREAT_ACTOR_GROUP,
} from '../../../../schema/stixDomainObject';
import { ENTITY_HOSTNAME, ENTITY_IPV4_ADDR, ENTITY_IPV6_ADDR } from '../../../../schema/stixCyberObservable';
import { STIX_SIGHTING_RELATIONSHIP } from '../../../../schema/stixSightingRelationship';
import { ENTITY_TYPE_VULNERABILITY } from '../../../vulnerability/vulnerability-types';
import { ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL } from '../../../threatActorIndividual/threatActorIndividual-types';

type Kind = 'ASSET' | 'ATTACK_PATTERN' | 'VULNERABILITY' | 'THREAT' | 'ALERT';
type Normalise = (kind: Kind, key: string | null | undefined) => string | null;

/** One OpenCTI object the caller can read, with the kind and the keys it is matched on. */
export interface CounterpartSource {
  id: string;
  kind: Kind;
  keys: string[];
}

const THREAT_TYPES = new Set([
  ENTITY_TYPE_CONTAINER_REPORT,
  ENTITY_TYPE_THREAT_ACTOR_GROUP,
  ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL,
  ENTITY_TYPE_INTRUSION_SET,
  ENTITY_TYPE_MALWARE,
  ENTITY_TYPE_CAMPAIGN,
]);
const ALERT_TYPES = new Set([ENTITY_TYPE_INCIDENT, STIX_SIGHTING_RELATIONSHIP]);
// The most external references read for one alert source: an alert carries a handful.
const MAX_ALERT_LINKS = 20;

/** The kind an entity type is matched as, and its key (alerts: read from the external references). */
export const counterpartKindOf = (entityType: string): Kind | null => {
  if (entityType === ENTITY_TYPE_IDENTITY_SYSTEM || entityType === ENTITY_HOSTNAME
    || entityType === ENTITY_IPV4_ADDR || entityType === ENTITY_IPV6_ADDR) {
    return 'ASSET';
  }
  if (entityType === ENTITY_TYPE_ATTACK_PATTERN) {
    return 'ATTACK_PATTERN';
  }
  if (entityType === ENTITY_TYPE_VULNERABILITY) {
    return 'VULNERABILITY';
  }
  if (THREAT_TYPES.has(entityType)) {
    return 'THREAT';
  }
  if (ALERT_TYPES.has(entityType)) {
    return 'ALERT';
  }
  return null;
};

export const counterpartKeyOf = (kind: Kind, object: any): string | null => {
  switch (kind) {
    case 'ASSET':
      return object.entity_type === ENTITY_TYPE_IDENTITY_SYSTEM ? object.name : object.value;
    case 'ATTACK_PATTERN':
      return object.x_mitre_id ?? null;
    case 'VULNERABILITY':
      return object.name ?? null;
    case 'THREAT':
      return object.standard_id ?? null;
    default:
      return null;
  }
};

/**
 * The counterpart keys of the given OpenCTI objects, read on the server under the caller's rights:
 * an id the caller cannot read is absent from the answer, and so is an object with no valid key
 * (Q2.2: never sent, never answered not_found). Alerts are matched on their external reference URLs.
 */
export const counterpartKeysOf = async (
  context: AuthContext,
  user: AuthUser,
  ids: string[],
  normalise: Normalise,
): Promise<CounterpartSource[]> => {
  const unique = [...new Set(ids.filter((id) => typeof id === 'string' && id.length > 0))];
  if (unique.length === 0) {
    return [];
  }
  const objects = await internalFindByIds<BasicStoreObject>(context, user, unique) as BasicStoreObject[];
  const byId = new Map<string, BasicStoreObject>();
  for (const object of objects) {
    unique.filter((id) => id === object.internal_id || id === object.standard_id || (object.x_opencti_stix_ids as string[] | undefined)?.includes(id))
      .forEach((id) => byId.set(id, object));
  }
  const alertIds = unique.filter((id) => {
    const object = byId.get(id);
    return object && counterpartKindOf(object.entity_type) === 'ALERT';
  });
  const linksByObject = new Map<string, string[]>();
  if (alertIds.length > 0) {
    const internalIds = [...new Set(alertIds.map((id) => byId.get(id)!.internal_id))];
    const relations = await fullRelationsList<BasicStoreRelation>(context, user, RELATION_EXTERNAL_REFERENCE, {
      fromId: internalIds,
      toTypes: [ENTITY_TYPE_EXTERNAL_REFERENCE],
    });
    const refIds = [...new Set(relations.map((r) => r.toId))];
    const refs = refIds.length > 0 ? await internalFindByIds<BasicStoreObject>(context, user, refIds) as BasicStoreObject[] : [];
    const urlByRef = new Map(refs.map((ref) => [ref.internal_id, (ref as any).url as string | undefined]));
    for (const relation of relations) {
      const url = urlByRef.get(relation.toId);
      if (url) {
        const links = linksByObject.get(relation.fromId) ?? [];
        if (links.length < MAX_ALERT_LINKS) {
          links.push(url);
        }
        linksByObject.set(relation.fromId, links);
      }
    }
  }
  const sources: CounterpartSource[] = [];
  for (const id of unique) {
    const object = byId.get(id);
    const kind = object ? counterpartKindOf(object.entity_type) : null;
    if (!object || !kind) {
      continue;
    }
    const raw = kind === 'ALERT' ? (linksByObject.get(object.internal_id) ?? []) : [counterpartKeyOf(kind, object)];
    const keys = [...new Set(raw.map((key) => normalise(kind, key)).filter((key): key is string => !!key))];
    if (keys.length > 0) {
      sources.push({ id, kind, keys });
    }
  }
  return sources;
};
