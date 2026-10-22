import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreBase, BasicStoreRelation } from '../../types/store';
import { computeQueryIndices, elFindByIds, elList } from '../../database/engine';
import { buildRelationsFilter } from '../../database/middleware-loader';
import { ABSTRACT_STIX_CORE_RELATIONSHIP } from '../../schema/general';
import {
  ENTITY_TYPE_ATTACK_PATTERN,
  ENTITY_TYPE_CAMPAIGN,
  ENTITY_TYPE_CONTAINER_REPORT,
  ENTITY_TYPE_IDENTITY_INDIVIDUAL,
  ENTITY_TYPE_IDENTITY_SECTOR,
  ENTITY_TYPE_INFRASTRUCTURE,
  ENTITY_TYPE_INTRUSION_SET,
  ENTITY_TYPE_LOCATION_CITY,
  ENTITY_TYPE_LOCATION_COUNTRY,
  ENTITY_TYPE_LOCATION_REGION,
  ENTITY_TYPE_MALWARE,
  ENTITY_TYPE_THREAT_ACTOR_GROUP,
  ENTITY_TYPE_TOOL,
} from '../../schema/stixDomainObject';
import { ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL } from '../threatActorIndividual/threatActorIndividual-types';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../organization/organization-types';
import { ENTITY_TYPE_LOCATION_ADMINISTRATIVE_AREA } from '../administrativeArea/administrativeArea-types';
import {
  ENTITY_AUTONOMOUS_SYSTEM,
  ENTITY_DOMAIN_NAME,
  ENTITY_HASHED_OBSERVABLE_X509_CERTIFICATE,
  ENTITY_HOSTNAME,
  ENTITY_IPV4_ADDR,
  ENTITY_IPV6_ADDR,
  ENTITY_URL,
} from '../../schema/stixCyberObservable';
import { RELATION_TARGETS, RELATION_USES } from '../../schema/stixCoreRelationship';
import { RELATION_OBJECT } from '../../schema/stixRefRelationship';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
import { READ_ENTITIES_INDICES, READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED } from '../../database/utils';
import type { GraphFeatureFamily, GraphFeatureProfile, GraphFeatureProfileKind, GraphFeatureSets } from './graphAnalytics-types';

export interface GraphProfileSpec {
  // entities are only compared with entities of the same group
  group: string;
  kind: GraphFeatureProfileKind;
  entityTypes: string[];
}

export const THREAT_ENTITY_TYPES = [ENTITY_TYPE_INTRUSION_SET, ENTITY_TYPE_THREAT_ACTOR_GROUP, ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL, ENTITY_TYPE_CAMPAIGN];
export const INFRASTRUCTURE_ENTITY_TYPES = [
  ENTITY_TYPE_INFRASTRUCTURE,
  ENTITY_DOMAIN_NAME,
  ENTITY_HOSTNAME,
  ENTITY_IPV4_ADDR,
  ENTITY_IPV6_ADDR,
  ENTITY_URL,
  ENTITY_HASHED_OBSERVABLE_X509_CERTIFICATE,
];

export const GRAPH_PROFILE_SPECS: GraphProfileSpec[] = [
  { group: 'threat', kind: 'threat', entityTypes: THREAT_ENTITY_TYPES },
  { group: 'malware', kind: 'threat', entityTypes: [ENTITY_TYPE_MALWARE] },
  { group: 'infrastructure', kind: 'infrastructure', entityTypes: [ENTITY_TYPE_INFRASTRUCTURE] },
  { group: 'domain', kind: 'infrastructure', entityTypes: [ENTITY_DOMAIN_NAME, ENTITY_HOSTNAME] },
  { group: 'ip', kind: 'infrastructure', entityTypes: [ENTITY_IPV4_ADDR, ENTITY_IPV6_ADDR] },
  { group: 'url', kind: 'infrastructure', entityTypes: [ENTITY_URL] },
  { group: 'certificate', kind: 'infrastructure', entityTypes: [ENTITY_HASHED_OBSERVABLE_X509_CERTIFICATE] },
  { group: 'report', kind: 'report', entityTypes: [ENTITY_TYPE_CONTAINER_REPORT] },
];

export const GRAPH_PROFILED_ENTITY_TYPES = GRAPH_PROFILE_SPECS.flatMap((spec) => spec.entityTypes);

export const getGraphProfileSpec = (entityType: string): GraphProfileSpec | undefined => {
  return GRAPH_PROFILE_SPECS.find((spec) => spec.entityTypes.includes(entityType));
};

export const isSameComparisonGroup = (entityType: string, otherEntityType: string): boolean => {
  const spec = getGraphProfileSpec(entityType);
  return !!spec && spec.group === getGraphProfileSpec(otherEntityType)?.group;
};

const VICTIM_TYPES = [
  ENTITY_TYPE_IDENTITY_SECTOR,
  ENTITY_TYPE_IDENTITY_ORGANIZATION,
  ENTITY_TYPE_IDENTITY_INDIVIDUAL,
  ENTITY_TYPE_LOCATION_COUNTRY,
  ENTITY_TYPE_LOCATION_REGION,
  ENTITY_TYPE_LOCATION_CITY,
  ENTITY_TYPE_LOCATION_ADMINISTRATIVE_AREA,
];
const IP_TYPES = [ENTITY_IPV4_ADDR, ENTITY_IPV6_ADDR];
const NAME_TYPES = [ENTITY_DOMAIN_NAME, ENTITY_HOSTNAME];
const REGISTRAR_TYPES = [ENTITY_TYPE_IDENTITY_ORGANIZATION, ENTITY_TYPE_IDENTITY_INDIVIDUAL];

export type NeighborDirection = 'out' | 'in';

/** Family of the neighbor of a threat (intrusion set, threat actor, campaign, malware), or null if not a feature. */
export const classifyThreatNeighbor = (relationshipType: string, direction: NeighborDirection, neighborType: string): GraphFeatureFamily | null => {
  if (direction !== 'out') return null;
  if (relationshipType === RELATION_USES) {
    if (neighborType === ENTITY_TYPE_ATTACK_PATTERN) return 'techniques';
    if (neighborType === ENTITY_TYPE_TOOL) return 'tools';
    if (neighborType === ENTITY_TYPE_MALWARE) return 'malware';
  }
  if (neighborType === ENTITY_TYPE_INFRASTRUCTURE) return 'infrastructure';
  if (relationshipType === RELATION_TARGETS && VICTIM_TYPES.includes(neighborType)) return 'victims';
  return null;
};

/** Family of the neighbor of an infrastructure element (infrastructure, domain, ip, url, certificate), in both directions. */
export const classifyInfrastructureNeighbor = (sourceType: string, neighborType: string): GraphFeatureFamily | null => {
  if (neighborType === ENTITY_HASHED_OBSERVABLE_X509_CERTIFICATE) return 'certificates';
  if (neighborType === ENTITY_AUTONOMOUS_SYSTEM) return 'asn';
  if (REGISTRAR_TYPES.includes(neighborType)) return 'registrar';
  if (NAME_TYPES.includes(neighborType)) {
    // co-hosted names for an address, name servers / related names for a name or an infrastructure
    return IP_TYPES.includes(sourceType) ? 'hosting' : 'nameservers';
  }
  if (IP_TYPES.includes(neighborType)) return 'hosting';
  if (neighborType === ENTITY_TYPE_INFRASTRUCTURE) return 'infrastructure';
  if (neighborType === ENTITY_TYPE_MALWARE) return 'malware';
  return null;
};

export interface FeatureExtractionOptions {
  maxPerFamily: number;
  maxRelationships: number;
  // A relationship can be visible while one of its endpoints is not: a caller other than the manager must check both
  checkEndpointsAccess?: boolean;
}

export const keepAccessibleEndpoints = async (
  context: AuthContext,
  user: AuthUser,
  relations: BasicStoreRelation[],
  checkEndpointsAccess: boolean | undefined,
): Promise<BasicStoreRelation[]> => {
  if (!checkEndpointsAccess || relations.length === 0) return relations;
  const ids = Array.from(new Set(relations.flatMap((relation) => [relation.fromId, relation.toId])));
  const accessible = await elFindByIds<BasicStoreBase>(context, user, ids, { indices: READ_ENTITIES_INDICES, baseData: true }) as BasicStoreBase[];
  const accessibleIds = new Set(accessible.map((element) => element.internal_id));
  return relations.filter((relation) => accessibleIds.has(relation.fromId) && accessibleIds.has(relation.toId));
};

const addFeature = (features: GraphFeatureSets, family: GraphFeatureFamily, id: string, maxPerFamily: number) => {
  const list = features[family] ?? [];
  if (list.length < maxPerFamily && !list.includes(id)) {
    list.push(id);
    features[family] = list;
  }
};

const emptyProfile = (id: string, entityType: string, kind: GraphFeatureProfileKind): GraphFeatureProfile => ({
  id,
  entity_type: entityType,
  kind,
  features: {},
  relation_vector: {},
});

export interface AnalyticsRelationsArgs {
  fromOrToId?: string[];
  fromId?: string[];
  toId?: string[];
  fromTypes?: string[];
  toTypes?: string[];
}

export const listAnalyticsRelations = async (
  context: AuthContext,
  user: AuthUser,
  types: string[],
  args: AnalyticsRelationsArgs,
  maxSize: number,
): Promise<BasicStoreRelation[]> => {
  const indices = computeQueryIndices(undefined, types, false) as string[];
  const paginateArgs = buildRelationsFilter(types, args);
  return elList<BasicStoreRelation>(context, user, indices, {
    ...paginateArgs,
    baseData: true,
    first: Math.min(maxSize, 5000),
    maxSize,
  });
};

/**
 * Build the feature profile of entities (ids only). All the queries run as `user`: the manager uses its system user
 * to precompute, the matrix query uses the caller so a score never relies on knowledge the caller cannot access.
 */
export const loadFeatureProfiles = async (
  context: AuthContext,
  user: AuthUser,
  entities: Array<{ id: string; entity_type: string }>,
  opts: FeatureExtractionOptions,
): Promise<Map<string, GraphFeatureProfile>> => {
  const profiles = new Map<string, GraphFeatureProfile>();
  const byKind: Record<GraphFeatureProfileKind, string[]> = { threat: [], infrastructure: [], report: [] };
  entities.forEach((entity) => {
    const spec = getGraphProfileSpec(entity.entity_type);
    if (!spec) return;
    profiles.set(entity.id, emptyProfile(entity.id, entity.entity_type, spec.kind));
    byKind[spec.kind].push(entity.id);
  });
  const relationalIds = [...byKind.threat, ...byKind.infrastructure];
  if (relationalIds.length > 0) {
    const listed = await listAnalyticsRelations(context, user, [ABSTRACT_STIX_CORE_RELATIONSHIP], { fromOrToId: relationalIds }, opts.maxRelationships);
    const relations = await keepAccessibleEndpoints(context, user, listed, opts.checkEndpointsAccess);
    relations.forEach((relation) => {
      const sides: Array<{ self: string; neighbor: string; neighborType: string; direction: NeighborDirection }> = [
        { self: relation.fromId, neighbor: relation.toId, neighborType: relation.toType, direction: 'out' },
        { self: relation.toId, neighbor: relation.fromId, neighborType: relation.fromType, direction: 'in' },
      ];
      sides.forEach(({ self, neighbor, neighborType, direction }) => {
        const profile = profiles.get(self);
        if (!profile || profile.kind === 'report' || neighbor === self) return;
        profile.relation_vector[relation.relationship_type] = (profile.relation_vector[relation.relationship_type] ?? 0) + 1;
        const family = profile.kind === 'threat'
          ? classifyThreatNeighbor(relation.relationship_type, direction, neighborType)
          : classifyInfrastructureNeighbor(profile.entity_type, neighborType);
        if (family) addFeature(profile.features, family, neighbor, opts.maxPerFamily);
      });
    });
  }
  if (byKind.infrastructure.length > 0) {
    // report co-occurrence: containers referencing the element
    const listed = await listAnalyticsRelations(context, user, [RELATION_OBJECT], { toId: byKind.infrastructure }, opts.maxRelationships);
    const containment = await keepAccessibleEndpoints(context, user, listed, opts.checkEndpointsAccess);
    containment.forEach((relation) => {
      const profile = profiles.get(relation.toId);
      if (profile && relation.fromType === ENTITY_TYPE_CONTAINER_REPORT) {
        addFeature(profile.features, 'reports', relation.fromId, opts.maxPerFamily);
      }
    });
  }
  if (byKind.report.length > 0) {
    const listed = await listAnalyticsRelations(context, user, [RELATION_OBJECT], { fromId: byKind.report }, opts.maxRelationships);
    const objects = await keepAccessibleEndpoints(context, user, listed, opts.checkEndpointsAccess);
    objects.forEach((relation) => {
      const profile = profiles.get(relation.fromId);
      if (!profile) return;
      profile.relation_vector[relation.toType] = (profile.relation_vector[relation.toType] ?? 0) + 1;
      addFeature(profile.features, 'objects', relation.toId, opts.maxPerFamily);
    });
  }
  return profiles;
};

// Relationship types and opposite sides used to find candidates sharing a feature with a profile.
export interface CandidateQuery {
  family: GraphFeatureFamily;
  relationshipTypes: string[];
  // side of the relationship on which the feature id is
  featureSide: 'from' | 'to' | 'any';
}

export const candidateQueriesForKind = (kind: GraphFeatureProfileKind): CandidateQuery[] => {
  if (kind === 'threat') {
    return [
      { family: 'techniques', relationshipTypes: [RELATION_USES], featureSide: 'to' },
      { family: 'tools', relationshipTypes: [RELATION_USES], featureSide: 'to' },
      { family: 'malware', relationshipTypes: [RELATION_USES], featureSide: 'to' },
      { family: 'infrastructure', relationshipTypes: [ABSTRACT_STIX_CORE_RELATIONSHIP], featureSide: 'to' },
      { family: 'victims', relationshipTypes: [RELATION_TARGETS], featureSide: 'to' },
    ];
  }
  if (kind === 'infrastructure') {
    return [
      { family: 'certificates', relationshipTypes: [ABSTRACT_STIX_CORE_RELATIONSHIP], featureSide: 'any' },
      { family: 'asn', relationshipTypes: [ABSTRACT_STIX_CORE_RELATIONSHIP], featureSide: 'any' },
      { family: 'registrar', relationshipTypes: [ABSTRACT_STIX_CORE_RELATIONSHIP], featureSide: 'any' },
      { family: 'nameservers', relationshipTypes: [ABSTRACT_STIX_CORE_RELATIONSHIP], featureSide: 'any' },
      { family: 'hosting', relationshipTypes: [ABSTRACT_STIX_CORE_RELATIONSHIP], featureSide: 'any' },
      { family: 'infrastructure', relationshipTypes: [ABSTRACT_STIX_CORE_RELATIONSHIP], featureSide: 'any' },
      { family: 'malware', relationshipTypes: [ABSTRACT_STIX_CORE_RELATIONSHIP], featureSide: 'any' },
      { family: 'reports', relationshipTypes: [RELATION_OBJECT], featureSide: 'from' },
    ];
  }
  return [{ family: 'objects', relationshipTypes: [RELATION_OBJECT], featureSide: 'to' }];
};

export const RELATIONSHIP_INDICES_FOR_ANALYTICS = READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED;
export const PATH_DEFAULT_RELATIONSHIP_TYPES = [ABSTRACT_STIX_CORE_RELATIONSHIP, STIX_SIGHTING_RELATIONSHIP];
