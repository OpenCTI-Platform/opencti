import { addCitizenshipDocument, findCitizenshipDocumentPaginated, findById } from '../domain/citizenshipDocument';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDelete,
  stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField,
} from '../domain/stixDomainObject';
import { ENTITY_TYPE_IDENTITY_CITIZENSHIP_DOCUMENT } from '../schema/stixDomainObject';

// TODO REVIEW

const citizenshipDocumentResolvers = {
  Query: {
    citizenshipDocument: (_, { id }, context) => findById(context, context.user, id),
    citizenshipDocuments: (_, args, context) => findCitizenshipDocumentPaginated(context, context.user, args),
  },
  Mutation: {
    citizenshipDocumentEdit: (_, { id }, context) => ({
      delete: async () => {
        // Use the type-checking version that validates the entity type
        return stixDomainObjectDelete(context, context.user, id, ENTITY_TYPE_IDENTITY_CITIZENSHIP_DOCUMENT);
      },
      fieldPatch: ({ input, commitMessage, references }) => stixDomainObjectEditField(context, context.user, id, input, { commitMessage, references }),
      contextPatch: ({ input }) => stixDomainObjectEditContext(context, context.user, id, input),
      contextClean: () => stixDomainObjectCleanContext(context, context.user, id),
      relationAdd: ({ input }) => stixDomainObjectAddRelation(context, context.user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) => stixDomainObjectDeleteRelation(context, context.user, id, toId, relationshipType),
    }),
    citizenshipDocumentAdd: (_, { input }, context) => addCitizenshipDocument(context, context.user, input),
  },
};

export default citizenshipDocumentResolvers;
