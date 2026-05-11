import * as R from 'ramda';
import { createEntity } from '../database/middleware';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { isEmptyField, READ_INDEX_STIX_DOMAIN_OBJECTS, READ_INDEX_STIX_META_OBJECTS } from '../database/utils';
import { ENTITY_TYPE_ATTACK_PATTERN, ENTITY_TYPE_COURSE_OF_ACTION, ENTITY_TYPE_DATA_COMPONENT } from '../schema/stixDomainObject';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../schema/general';
import { RELATION_DETECTS, RELATION_MITIGATES, RELATION_SUBTECHNIQUE_OF } from '../schema/stixCoreRelationship';
import { ENTITY_TYPE_KILL_CHAIN_PHASE } from '../schema/stixMetaObject';
import { RELATION_KILL_CHAIN_PHASE } from '../schema/stixRefRelationship';
import {
  type EntityOptions,
  findEntitiesIdsWithRelations,
  fullEntitiesList,
  fullRelationsList,
  pageEntitiesConnection,
  pageRegardingEntitiesConnection,
  storeLoadById,
} from '../database/middleware-loader';
import type { AuthContext, AuthUser } from '../types/user';
import type { BasicStoreCommon, BasicStoreRelation } from '../types/store';
import { type AttackPatternAddInput, FilterMode } from '../generated/graphql';

export const findById = (context: AuthContext, user: AuthUser, attackPatternId: string) => {
  return storeLoadById(context, user, attackPatternId, ENTITY_TYPE_ATTACK_PATTERN);
};

export const findAttackPatternPaginated = (context: AuthContext, user: AuthUser, args: EntityOptions<BasicStoreCommon>) => {
  return pageEntitiesConnection(context, user, [ENTITY_TYPE_ATTACK_PATTERN], args);
};

export const addAttackPattern = async (context: AuthContext, user: AuthUser, attackPattern: AttackPatternAddInput) => {
  let xMitreId = null;
  if (isEmptyField(attackPattern.x_mitre_id)) {
    // Extract x_mitre_id from name if not already provided
    // Match patterns like T0015.001, T0015, FT048
    const mitreIdMatch = attackPattern.name?.match(/\b([TF]T?\d+(?:\.\d+)?)\b/);
    if (mitreIdMatch) {
      xMitreId = mitreIdMatch[1];
    }
  }
  const attackPatternToCreate = xMitreId ? R.assoc('x_mitre_id', xMitreId, attackPattern) : attackPattern;
  const created = await createEntity(context, user, attackPatternToCreate, ENTITY_TYPE_ATTACK_PATTERN);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};

export const parentAttackPatternsPaginated = async (context: AuthContext, user: AuthUser, attackPatternId: string, args: EntityOptions<BasicStoreCommon>) => {
  return pageRegardingEntitiesConnection(context, user, attackPatternId, RELATION_SUBTECHNIQUE_OF, ENTITY_TYPE_ATTACK_PATTERN, false, args);
};

export const childAttackPatternsPaginated = async (context: AuthContext, user: AuthUser, attackPatternId: string, args: EntityOptions<BasicStoreCommon>) => {
  return pageRegardingEntitiesConnection(context, user, attackPatternId, RELATION_SUBTECHNIQUE_OF, ENTITY_TYPE_ATTACK_PATTERN, true, args);
};

export const batchIsSubAttackPattern = async (context: AuthContext, user: AuthUser, attackPatternsIds: string[]) => {
  const resultIds = await findEntitiesIdsWithRelations(context, user, attackPatternsIds, RELATION_SUBTECHNIQUE_OF, ENTITY_TYPE_ATTACK_PATTERN, false);
  return attackPatternsIds.map((id) => {
    return resultIds.includes(id);
  });
};

export const coursesOfActionPaginated = async (context: AuthContext, user: AuthUser, attackPatternId: string, args: EntityOptions<BasicStoreCommon>) => {
  return pageRegardingEntitiesConnection(context, user, attackPatternId, RELATION_MITIGATES, ENTITY_TYPE_COURSE_OF_ACTION, true, args);
};

export const dataComponentsPaginated = async (context: AuthContext, user: AuthUser, attackPatternId: string, args: EntityOptions<BasicStoreCommon>) => {
  return pageRegardingEntitiesConnection(context, user, attackPatternId, RELATION_DETECTS, ENTITY_TYPE_DATA_COMPONENT, true, args);
};

export const getAttackPatternsMatrix = async (context: AuthContext, user: AuthUser) => {
  const attackPatternsArgs = {
    withoutRels: false, // Must be replace by relation queries
    indices: [READ_INDEX_STIX_DOMAIN_OBJECTS],
    filters: { mode: FilterMode.And, filters: [{ key: ['revoked'], values: ['false'] }], filterGroups: [] },
  };

  // 1. Load all data

  const allAttackPatterns = await fullEntitiesList(context, user, [ENTITY_TYPE_ATTACK_PATTERN], attackPatternsArgs);
  const allAttackPatternsById = new Map(allAttackPatterns.map((a) => [a.id, a]));
  const allKillChainPhases = await fullEntitiesList(context, user, [ENTITY_TYPE_KILL_CHAIN_PHASE], { indices: [READ_INDEX_STIX_META_OBJECTS] });
  const subTechniquesRelations = await fullRelationsList<BasicStoreRelation>(context, user, RELATION_SUBTECHNIQUE_OF);

  // 2. Pre-compute indexes

  const subTechniqueIds = new Set(subTechniquesRelations.map((s) => s.fromId));
  // This map regroups sub attack patterns by the parent attack pattern
  const subTechniquesByParentId = new Map<string, { attack_pattern_id: string; name: string; description?: string }[]>();
  const searchTextPartsByParentId = new Map<string, string[]>();
  for (const s of subTechniquesRelations) {
    const subAP = allAttackPatternsById.get(s.fromId);
    if (subAP) {
      if (!subTechniquesByParentId.has(s.toId)) {
        subTechniquesByParentId.set(s.toId, []);
        searchTextPartsByParentId.set(s.toId, []);
      }
      subTechniquesByParentId.get(s.toId)!.push({ attack_pattern_id: subAP.id, name: subAP.name, description: subAP.description });
      searchTextPartsByParentId.get(s.toId)!.push(`${subAP.x_mitre_id} ${subAP.name} ${subAP.description}`);
    }
  }

  // This map regroups attack patterns by killchainphases
  // sub attack patterns are ignored because they are managed differently (see first map above)
  const parentAPsByKcpId = new Map<string, typeof allAttackPatterns>();
  for (const ap of allAttackPatterns) {
    if (subTechniqueIds.has(ap.id)) continue;
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    const kcpIds: string[] = ap[RELATION_KILL_CHAIN_PHASE] ?? [];
    for (const kcpId of kcpIds) {
      if (!parentAPsByKcpId.has(kcpId)) parentAPsByKcpId.set(kcpId, []);
      parentAPsByKcpId.get(kcpId)!.push(ap);
    }
  }

  // 3. Build result

  const attackPatternsOfPhases = [];
  for (const kcp of allKillChainPhases) {
    // Get attack patterns for this killchainphase using map #2
    const phaseAPs = parentAPsByKcpId.get(kcp.id) ?? [];
    if (phaseAPs.length === 0) continue;
    attackPatternsOfPhases.push({
      kill_chain_id: kcp.id,
      kill_chain_name: kcp.kill_chain_name,
      phase_name: kcp.phase_name,
      x_opencti_order: kcp.x_opencti_order,
      attackPatterns: phaseAPs.map((ap) => ({
        attack_pattern_id: ap.id,
        name: ap.name,
        description: ap.description,
        x_mitre_id: ap.x_mitre_id,
        // Add sub attack patterns using map #1
        subAttackPatterns: subTechniquesByParentId.get(ap.id) ?? [],
        subAttackPatternsSearchText: (searchTextPartsByParentId.get(ap.id) ?? []).join(' | '),
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-ignore
        killChainPhasesIds: [...ap[RELATION_KILL_CHAIN_PHASE]],
      })),
    });
  }
  return { attackPatternsOfPhases };
};
