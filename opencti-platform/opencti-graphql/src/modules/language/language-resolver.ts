import type { EditUserContext, Resolvers, StixCoreRelationshipConnection, User } from '../../generated/graphql';
import { addLanguage, findAll, findById } from './language-domain';
import { batchCreatedBy, stixCoreRelationships } from '../../domain/stixCoreObject';
import { batchLoader, stixLoadByIdStringify } from '../../database/middleware';
import { creator } from '../../domain/log';
import { ABSTRACT_STIX_CORE_OBJECT } from '../../schema/general';
import { fetchEditContext } from '../../database/redis';

const createdByLoader = batchLoader(batchCreatedBy);

const languageResolvers: Resolvers = {
  Query: {
    language: (_, { id }, { user }) => findById(user, id),
    languages: (_, args, { user }) => findAll(user, args),
  },
  Language: {
    // Resolution
    createdBy: (stixCoreObject, _, { user }) => createdByLoader.load(stixCoreObject.id, user),
    stixCoreRelationships: (stixCoreObject, args, { user }) => {
      return stixCoreRelationships(user, stixCoreObject.id, args) as unknown as StixCoreRelationshipConnection;
    },
    // Technical
    creator: (stixCoreObject, _, { user }) => {
      return creator(user, stixCoreObject.id, ABSTRACT_STIX_CORE_OBJECT) as unknown as User;
    },
    toStix: (stixCoreObject, _, { user }) => stixLoadByIdStringify(user, stixCoreObject.id),
    editContext: (stixCoreObject) => {
      return fetchEditContext(stixCoreObject.id) as unknown as Array<EditUserContext>;
    },
  },
  Mutation: {
    languageAdd: (_, { input }, { user }) => addLanguage(user, input),
  },
};

export default languageResolvers;
