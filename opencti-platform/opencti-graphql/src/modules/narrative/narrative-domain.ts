import type { AuthContext, AuthUser } from '../../types/user';
import { batchListThroughGetFrom, batchListThroughGetTo, createEntity } from '../../database/middleware';
import { notify } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../schema/general';
import type { NarrativeAddInput, QueryNarrativesArgs } from '../../generated/graphql';
import { listEntitiesPaginated, storeLoadById } from '../../database/middleware-loader';
import { BasicStoreEntityNarrative, ENTITY_TYPE_NARRATIVE } from './narrative-types';
import { RELATION_SUBNARRATIVE_OF } from '../../schema/stixCoreRelationship';

export const findById = (context: AuthContext, user: AuthUser, narrativeId: string): BasicStoreEntityNarrative => {
  return storeLoadById(context, user, narrativeId, ENTITY_TYPE_NARRATIVE) as unknown as BasicStoreEntityNarrative;
};

export const findAll = (context: AuthContext, user: AuthUser, opts: QueryNarrativesArgs) => {
  return listEntitiesPaginated<BasicStoreEntityNarrative>(context, user, [ENTITY_TYPE_NARRATIVE], opts);
};

export const addNarrative = async (context: AuthContext, user: AuthUser, narrative: NarrativeAddInput) => {
  const created = await createEntity(context, user, narrative, ENTITY_TYPE_NARRATIVE);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};

export const batchParentNarratives = (context: AuthContext, user: AuthUser, narrativeIds: Array<string>) => {
  return batchListThroughGetTo(context, user, narrativeIds, RELATION_SUBNARRATIVE_OF, ENTITY_TYPE_NARRATIVE);
};

export const batchSubNarratives = (context: AuthContext, user: AuthUser, narrativeIds: Array<string>) => {
  return batchListThroughGetFrom(context, user, narrativeIds, RELATION_SUBNARRATIVE_OF, ENTITY_TYPE_NARRATIVE);
};

export const batchIsSubNarrative = async (context: AuthContext, user: AuthUser, narrativeIds: Array<string>) => {
  const batchNarratives = await batchListThroughGetTo(
    context,
    user,
    narrativeIds,
    RELATION_SUBNARRATIVE_OF,
    ENTITY_TYPE_NARRATIVE,
    { paginate: false }
  );
  return batchNarratives.map((b) => b.length > 0);
};
