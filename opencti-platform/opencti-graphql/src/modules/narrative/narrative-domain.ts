import type { AuthUser } from '../../types/user';
import { batchListThroughGetFrom, batchListThroughGetTo, createEntity, storeLoadById } from '../../database/middleware';
import { notify } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../schema/general';
import type { NarrativeAddInput, QueryNarrativesArgs } from '../../generated/graphql';
import { listEntitiesPaginated } from '../../database/middleware-loader';
import { BasicStoreEntityNarrative, ENTITY_TYPE_NARRATIVE, RELATION_SUBNARRATIVE_OF } from './narrative-types';
import { RELATION_SUBTECHNIQUE_OF } from '../../schema/stixCoreRelationship';
import { ENTITY_TYPE_ATTACK_PATTERN } from '../../schema/stixDomainObject';

export const findById = (user: AuthUser, narrativeId: string): BasicStoreEntityNarrative => {
  return storeLoadById(user, narrativeId, ENTITY_TYPE_NARRATIVE) as unknown as BasicStoreEntityNarrative;
};

export const findAll = (user: AuthUser, opts: QueryNarrativesArgs) => {
  return listEntitiesPaginated<BasicStoreEntityNarrative>(user, [ENTITY_TYPE_NARRATIVE], opts);
};

export const addNarrative = async (user: AuthUser, narrative: NarrativeAddInput) => {
  const created = await createEntity(user, narrative, ENTITY_TYPE_NARRATIVE);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};

export const batchParentNarratives = (user: AuthUser, narrativeIds: Array<string>) => {
  return batchListThroughGetTo(user, narrativeIds, RELATION_SUBNARRATIVE_OF, ENTITY_TYPE_NARRATIVE);
};

export const batchSubNarratives = (user: AuthUser, narrativeIds: Array<string>) => {
  return batchListThroughGetFrom(user, narrativeIds, RELATION_SUBNARRATIVE_OF, ENTITY_TYPE_NARRATIVE);
};

export const batchIsSubNarrative = async (user: AuthUser, narrativeIds: Array<string>) => {
  const batchNarratives = await batchListThroughGetTo(
    user,
    narrativeIds,
    RELATION_SUBTECHNIQUE_OF,
    ENTITY_TYPE_ATTACK_PATTERN,
    { paginate: false }
  );
  return batchNarratives.map((b) => b.length > 0);
};
