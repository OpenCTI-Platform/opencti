import { addCitizenshipDocument, findCitizenshipDocumentPaginated, findById, citizenshipDocumentDelete } from './citizenshipDocument-domain';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField,
} from '../../domain/stixDomainObject';
import type { Resolvers } from '../../generated/graphql';

const CitizenshipDocumentResolvers: Resolvers = {
  Query: {
    citizenshipDocument: (_, { id }, context) => findById(context, context.user, id),
    citizenshipDocuments: (_, args, context) => findCitizenshipDocumentPaginated(context, context.user, args),
  },
  Mutation: {
    citizenshipDocumentAdd: (_, { input }, context) => addCitizenshipDocument(context, context.user, input),
    citizenshipDocumentDelete: (_, { id }, context) => citizenshipDocumentDelete(context, context.user, id),
    citizenshipDocumentFieldPatch: (_, { id, input, commitMessage, references }, context) => {
      return stixDomainObjectEditField(context, context.user, id, input, { commitMessage, references });
    },
    citizenshipDocumentContextPatch: (_, { id, input }, context) => stixDomainObjectEditContext(context, context.user, id, input),
    citizenshipDocumentContextClean: (_, { id }, context) => stixDomainObjectCleanContext(context, context.user, id),
    citizenshipDocumentRelationAdd: (_, { id, input }, context) => stixDomainObjectAddRelation(context, context.user, id, input),
    citizenshipDocumentRelationDelete: (_, { id, toId, relationship_type: relationshipType }, context) => {
      return stixDomainObjectDeleteRelation(context, context.user, id, toId, relationshipType);
    },
  },
};

export default CitizenshipDocumentResolvers;
