import type { AuthContext, AuthUser } from '../../types/user';
import { createEntity } from '../../database/middleware';
import { notify } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../schema/general';
import type { LanguageAddInput, QueryLanguagesArgs } from '../../generated/graphql';
import { pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
import { type BasicStoreEntityLanguage, ENTITY_TYPE_LANGUAGE } from './language-types';

export const findById = (context: AuthContext, user: AuthUser, languageId: string): BasicStoreEntityLanguage => {
  return storeLoadById(context, user, languageId, ENTITY_TYPE_LANGUAGE) as unknown as BasicStoreEntityLanguage;
};

export const findLanguagePaginated = (context: AuthContext, user: AuthUser, opts: QueryLanguagesArgs) => {
  return pageEntitiesConnection<BasicStoreEntityLanguage>(context, user, [ENTITY_TYPE_LANGUAGE], opts);
};

export const addLanguage = async (context: AuthContext, user: AuthUser, language: LanguageAddInput) => {
  const created = await createEntity(context, user, language, ENTITY_TYPE_LANGUAGE);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
