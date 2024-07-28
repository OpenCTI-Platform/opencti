import type { AuthContext, AuthUser } from '../../types/user';
import { createEntity } from '../../database/middleware';
import { notify } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../schema/general';
import type { NarrativeAddInput, QueryNarrativesArgs } from '../../generated/graphql';
import { type EntityOptions, listEntitiesPaginated, listEntitiesThroughRelationsPaginated, storeLoadById } from '../../database/middleware-loader';
import { type BasicStoreEntityNarrative, ENTITY_TYPE_NARRATIVE } from './narrative-types';
import { RELATION_SUBNARRATIVE_OF } from '../../schema/stixCoreRelationship';
import type { BasicStoreCommon } from '../../types/store';

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

export const parentNarrativesPaginated = async <T extends BasicStoreCommon>(context: AuthContext, user: AuthUser, narrativeId: string, args: EntityOptions<BasicStoreCommon>) => {
  return listEntitiesThroughRelationsPaginated<T>(context, user, narrativeId, RELATION_SUBNARRATIVE_OF, ENTITY_TYPE_NARRATIVE, false, false, args);
};

export const childNarrativesPaginated = async <T extends BasicStoreCommon>(context: AuthContext, user: AuthUser, narrativeId: string, args: EntityOptions<BasicStoreCommon>) => {
  return listEntitiesThroughRelationsPaginated<T>(context, user, narrativeId, RELATION_SUBNARRATIVE_OF, ENTITY_TYPE_NARRATIVE, true, false, args);
};

export const isSubNarrative = async (context: AuthContext, user: AuthUser, narrativeId: string) => {
  const pagination = await parentNarrativesPaginated(context, user, narrativeId, { first: 1 });
  return pagination.edges.length > 0;
};
