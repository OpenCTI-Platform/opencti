import { createEntity } from '../database/middleware';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { READ_INDEX_STIX_DOMAIN_OBJECTS, READ_INDEX_STIX_META_OBJECTS } from '../database/utils';
import { ENTITY_TYPE_ATTACK_PATTERN, ENTITY_TYPE_COURSE_OF_ACTION, ENTITY_TYPE_DATA_COMPONENT } from '../schema/stixDomainObject';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../schema/general';
import { RELATION_DETECTS, RELATION_MITIGATES, RELATION_SUBTECHNIQUE_OF } from '../schema/stixCoreRelationship';
import { ENTITY_TYPE_KILL_CHAIN_PHASE } from '../schema/stixMetaObject';
import { RELATION_KILL_CHAIN_PHASE } from '../schema/stixRefRelationship';
import {
  batchListEntitiesThroughRelationsPaginated,
  type EntityOptions,
  findEntitiesIdsWithRelations,
  listAllEntities,
  listAllRelations,
  listEntities,
  listEntitiesThroughRelationsPaginated,
  storeLoadById
} from '../database/middleware-loader';
import type { AuthContext, AuthUser } from '../types/user';
import type { BasicStoreCommon, BasicStoreRelation } from '../types/store';
import { type AttackPatternAddInput, FilterMode } from '../generated/graphql';

export const findById = (context: AuthContext, user: AuthUser, attackPatternId: string) => {
  return storeLoadById(context, user, attackPatternId, ENTITY_TYPE_ATTACK_PATTERN);
};

export const findAll = (context: AuthContext, user: AuthUser, args: EntityOptions<BasicStoreCommon>) => {
  return listEntities(context, user, [ENTITY_TYPE_ATTACK_PATTERN], args);
};

export const addAttackPattern = async (context: AuthContext, user: AuthUser, attackPattern: AttackPatternAddInput) => {
  const created = await createEntity(context, user, attackPattern, ENTITY_TYPE_ATTACK_PATTERN);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};

export const parentAttackPatternsPaginated = async (context: AuthContext, user: AuthUser, attackPatternId: string, args: EntityOptions<BasicStoreCommon>) => {
  return listEntitiesThroughRelationsPaginated(context, user, attackPatternId, RELATION_SUBTECHNIQUE_OF, ENTITY_TYPE_ATTACK_PATTERN, false, args);
};
export const batchParentAttackPatternsPaginated = async (context: AuthContext, user: AuthUser, attackPatternsIds: string[], args: EntityOptions<BasicStoreCommon>) => {
  return batchListEntitiesThroughRelationsPaginated(context, user, attackPatternsIds, RELATION_SUBTECHNIQUE_OF, ENTITY_TYPE_ATTACK_PATTERN, false, args);
};

export const childAttackPatternsPaginated = async (context: AuthContext, user: AuthUser, attackPatternId: string, args: EntityOptions<BasicStoreCommon>) => {
  return listEntitiesThroughRelationsPaginated(context, user, attackPatternId, RELATION_SUBTECHNIQUE_OF, ENTITY_TYPE_ATTACK_PATTERN, true, args);
};
export const batchChildAttackPatternsPaginated = async (context: AuthContext, user: AuthUser, attackPatternsIds: string[], args: EntityOptions<BasicStoreCommon>) => {
  return batchListEntitiesThroughRelationsPaginated(context, user, attackPatternsIds, RELATION_SUBTECHNIQUE_OF, ENTITY_TYPE_ATTACK_PATTERN, true, args);
};

export const isSubAttackPattern = async (context: AuthContext, user: AuthUser, attackPatternId: string) => {
  const pagination = await parentAttackPatternsPaginated(context, user, attackPatternId, { first: 1 });
  return pagination.edges.length > 0;
};
export const batchIsSubAttackPattern = async (context: AuthContext, user: AuthUser, attackPatternsIds: string[]) => {
  const resultIds = await findEntitiesIdsWithRelations(context, user, attackPatternsIds, RELATION_SUBTECHNIQUE_OF, ENTITY_TYPE_ATTACK_PATTERN, false);
  return attackPatternsIds.map((id) => {
    return resultIds.includes(id);
  });
};

export const coursesOfActionPaginated = async (context: AuthContext, user: AuthUser, attackPatternId: string, args: EntityOptions<BasicStoreCommon>) => {
  return listEntitiesThroughRelationsPaginated(context, user, attackPatternId, RELATION_MITIGATES, ENTITY_TYPE_COURSE_OF_ACTION, true, args);
};

export const dataComponentsPaginated = async (context: AuthContext, user: AuthUser, attackPatternId: string, args: EntityOptions<BasicStoreCommon>) => {
  return listEntitiesThroughRelationsPaginated(context, user, attackPatternId, RELATION_DETECTS, ENTITY_TYPE_DATA_COMPONENT, true, args);
};

export const getAttackPatternsMatrix = async (context: AuthContext, user: AuthUser) => {
  const attackPatternsOfPhases = [];
  const attackPatternsArgs = {
    connectionFormat: false,
    indices: [READ_INDEX_STIX_DOMAIN_OBJECTS],
    filters: { mode: FilterMode.And, filters: [{ key: ['revoked'], values: ['false'] }], filterGroups: [] }
  };
  const allAttackPatterns = await listAllEntities(context, user, [ENTITY_TYPE_ATTACK_PATTERN], attackPatternsArgs);
  const allAttackPatternsById = new Map(allAttackPatterns.map((a) => [a.id, a]));
  const allKillChainPhases = await listAllEntities(context, user, [ENTITY_TYPE_KILL_CHAIN_PHASE], { connectionFormat: false, indices: [READ_INDEX_STIX_META_OBJECTS] });
  const subTechniquesRelations = await listAllRelations<BasicStoreRelation>(context, user, RELATION_SUBTECHNIQUE_OF, { connectionFormat: false });
  for (let index = 0; index < allKillChainPhases.length; index += 1) {
    const killChainPhase = allKillChainPhases[index];
    const phaseAttackPatterns = allAttackPatterns
      .filter((a) => {
        // filter sub attack patterns
        const isSub = subTechniquesRelations.some((s) => s.fromId === a.id);
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-ignore
        return !isSub && a[RELATION_KILL_CHAIN_PHASE] && a[RELATION_KILL_CHAIN_PHASE].includes(killChainPhase.id);
      })
      .map((attackPattern) => {
        const subAttackPatternsIds: string[] = [];
        let subAttackPatternsSearchText: string = '';
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-ignore
        if (attackPattern[RELATION_SUBTECHNIQUE_OF]) {
          const subAttackPatterns = subTechniquesRelations.filter((s) => s.toId === attackPattern.id);
          if (subAttackPatterns.length > 0) {
            subAttackPatterns.forEach((s) => {
              const subAttackPattern = allAttackPatternsById.get(s.fromId);
              if (subAttackPattern) {
                subAttackPatternsIds.push(subAttackPattern.id);
                subAttackPatternsSearchText += `${subAttackPattern.x_mitre_id} ${subAttackPattern.name} ${subAttackPattern.description} | `;
              }
            });
          }
        }
        return {
          attack_pattern_id: attackPattern.id,
          name: attackPattern.name,
          description: attackPattern.description,
          x_mitre_id: attackPattern.x_mitre_id,
          subAttackPatternsIds,
          subAttackPatternsSearchText,
          // eslint-disable-next-line @typescript-eslint/ban-ts-comment
          // @ts-ignore
          killChainPhasesIds: [...attackPattern[RELATION_KILL_CHAIN_PHASE]],
        };
      });
    if (phaseAttackPatterns.length > 0) {
      attackPatternsOfPhases.push({
        kill_chain_id: killChainPhase.id,
        kill_chain_name: killChainPhase.kill_chain_name,
        phase_name: killChainPhase.phase_name,
        x_opencti_order: killChainPhase.x_opencti_order,
        attackPatterns: phaseAttackPatterns,
      });
    }
  }
  return { attackPatternsOfPhases };
};
