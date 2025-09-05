import type { Resolvers } from '../../generated/graphql';
import { addLanguage, findLanguagePaginated, findById } from './language-domain';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDelete,
  stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField
} from '../../domain/stixDomainObject';

const languageResolvers: Resolvers = {
  Query: {
    language: (_, { id }, context) => findById(context, context.user, id),
    languages: (_, args, context) => findLanguagePaginated(context, context.user, args),
  },
  Mutation: {
    languageAdd: (_, { input }, context) => {
      return addLanguage(context, context.user, input);
    },
    languageDelete: (_, { id }, context) => {
      return stixDomainObjectDelete(context, context.user, id);
    },
    languageFieldPatch: (_, { id, input, commitMessage, references }, context) => {
      return stixDomainObjectEditField(context, context.user, id, input, { commitMessage, references });
    },
    languageContextPatch: (_, { id, input }, context) => {
      return stixDomainObjectEditContext(context, context.user, id, input);
    },
    languageContextClean: (_, { id }, context) => {
      return stixDomainObjectCleanContext(context, context.user, id);
    },
    languageRelationAdd: (_, { id, input }, context) => {
      return stixDomainObjectAddRelation(context, context.user, id, input);
    },
    languageRelationDelete: (_, { id, toId, relationship_type: relationshipType }, context) => {
      return stixDomainObjectDeleteRelation(context, context.user, id, toId, relationshipType);
    },
  },
};

export default languageResolvers;
