import { addIntrusionSet, findById, findIntrusionSetPaginated, locationsPaginated } from '../domain/intrusionSet';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDeleteRelation,
  stixDomainObjectDelete,
  stixDomainObjectEditContext,
  stixDomainObjectEditField,
} from '../domain/stixDomainObject';
import { ENTITY_TYPE_INTRUSION_SET } from '../schema/stixDomainObject';
import { findSecurityCoverageByCoveredId } from '../modules/securityCoverage/securityCoverage-domain';

const intrusionSetResolvers = {
  Query: {
    intrusionSet: (_, { id }, context) => findById(context, context.user, id),
    intrusionSets: (_, args, context) => findIntrusionSetPaginated(context, context.user, args),
  },
  IntrusionSet: {
    locations: (intrusionSet, args, context) => locationsPaginated(context, context.user, intrusionSet.id, args),
    securityCoverage: (intrusionSet, _, context) => findSecurityCoverageByCoveredId(context, context.user, intrusionSet.id),
  },
  Mutation: {
    intrusionSetEdit: (_, { id }, context) => ({
      delete: () => stixDomainObjectDelete(context, context.user, id, ENTITY_TYPE_INTRUSION_SET),
      fieldPatch: ({ input, commitMessage, references }) => stixDomainObjectEditField(context, context.user, id, input, { commitMessage, references }),
      contextPatch: ({ input }) => stixDomainObjectEditContext(context, context.user, id, input),
      contextClean: () => stixDomainObjectCleanContext(context, context.user, id),
      relationAdd: ({ input }) => stixDomainObjectAddRelation(context, context.user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) => stixDomainObjectDeleteRelation(context, context.user, id, toId, relationshipType),
    }),
    intrusionSetAdd: (_, { input }, context) => addIntrusionSet(context, context.user, input),
  },
};

export default intrusionSetResolvers;
