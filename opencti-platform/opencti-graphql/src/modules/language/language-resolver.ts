import type { Resolvers } from '../../generated/graphql';
import { addLanguage, findAll, findById } from './language-domain';
import { buildRefRelationKey } from '../../schema/general';
import { RELATION_CREATED_BY, RELATION_OBJECT_LABEL, RELATION_OBJECT_MARKING } from '../../schema/stixMetaRelationship';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDelete, stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField
} from '../../domain/stixDomainObject';

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
    languageAdd: (_, { input }, { user }) => {
      return addLanguage(user, input);
    },
    languageDelete: (_, { id }, { user }) => {
      return stixDomainObjectDelete(user, id);
    },
    languageFieldPatch: (_, { id, input, commitMessage, references }, { user }) => {
      return stixDomainObjectEditField(user, id, input, { commitMessage, references });
    },
    languageContextPatch: (_, { id, input }, { user }) => {
      return stixDomainObjectEditContext(user, id, input);
    },
    languageContextClean: (_, { id }, { user }) => {
      return stixDomainObjectCleanContext(user, id);
    },
    languageRelationAdd: (_, { id, input }, { user }) => {
      return stixDomainObjectAddRelation(user, id, input);
    },
    languageRelationDelete: (_, { id, toId, relationship_type: relationshipType }, { user }) => {
      return stixDomainObjectDeleteRelation(user, id, toId, relationshipType);
    },
  },
};

export default languageResolvers;
