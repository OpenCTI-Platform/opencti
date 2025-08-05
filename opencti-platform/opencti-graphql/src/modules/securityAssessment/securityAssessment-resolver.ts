import { addSecurityAssessment, findAll, findById, securityAssessmentDelete, securityAssessmentStixBundle, objectAssess } from './securityAssessment-domain';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField
} from '../../domain/stixDomainObject';
import type { Resolvers } from '../../generated/graphql';
import type { BasicStoreEntity } from '../../types/store';

const securityAssessmentResolvers: Resolvers = {
  Query: {
    securityAssessment: (_, { id }, context) => findById(context, context.user, id),
    securityAssessments: (_, args, context) => findAll(context, context.user, args),
  },
  SecurityAssessment: {
    objectAssess: (securityAssessment, _, context) => objectAssess<BasicStoreEntity>(context, context.user, securityAssessment.id),
    toStixBundle: (securityAssessment, _, context) => securityAssessmentStixBundle(context, context.user, securityAssessment.id)
  },
  Mutation: {
    securityAssessmentAdd: (_, { input }, context) => addSecurityAssessment(context, context.user, input),
    securityAssessmentDelete: (_, { id }, context) => securityAssessmentDelete(context, context.user, id),
    securityAssessmentFieldPatch: (_, { id, input, commitMessage, references }, context) => {
      return stixDomainObjectEditField(context, context.user, id, input, { commitMessage, references });
    },
    securityAssessmentContextPatch: (_, { id, input }, context) => stixDomainObjectEditContext(context, context.user, id, input),
    securityAssessmentContextClean: (_, { id }, context) => stixDomainObjectCleanContext(context, context.user, id),
    securityAssessmentRelationAdd: (_, { id, input }, context) => stixDomainObjectAddRelation(context, context.user, id, input),
    securityAssessmentRelationDelete: (_, { id, toId, relationship_type: relationshipType }, context) => {
      return stixDomainObjectDeleteRelation(context, context.user, id, toId, relationshipType);
    },
  },
};

export default securityAssessmentResolvers;
