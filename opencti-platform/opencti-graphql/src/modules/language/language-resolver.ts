import type { Resolvers } from '../../generated/graphql';
import { addLanguage, findAll, findById } from './language-domain';
import { buildRefRelationKey } from '../../schema/general';
import { RELATION_CREATED_BY, RELATION_OBJECT_LABEL, RELATION_OBJECT_MARKING } from '../../schema/stixMetaRelationship';

const languageResolvers: Resolvers = {
  Query: {
    language: (_, { id }, { user }) => findById(user, id),
    languages: (_, args, { user }) => findAll(user, args),
  },
  LanguagesFilter: {
    createdBy: buildRefRelationKey(RELATION_CREATED_BY),
    markedBy: buildRefRelationKey(RELATION_OBJECT_MARKING),
    labelledBy: buildRefRelationKey(RELATION_OBJECT_LABEL),
  },
  Mutation: {
    languageAdd: (_, { input }, { user }) => addLanguage(user, input),
  },
};

export default languageResolvers;
