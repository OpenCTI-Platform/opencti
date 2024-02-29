import {
  addReport,
  findAll,
  findById,
  reportContainsStixObjectOrStixRelationship,
  reportDeleteElementsCount,
  reportDeleteWithElements,
  reportsDistributionByEntity,
  reportsNumber,
  reportsNumberByAuthor,
  reportsNumberByEntity,
  reportsTimeSeries,
  reportsTimeSeriesByAuthor,
  reportsTimeSeriesByEntity,
} from '../domain/report';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDelete,
  stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField,
} from '../domain/stixDomainObject';
import { distributionEntities } from '../database/middleware';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../schema/stixDomainObject';
import { loadThroughDenormalized } from './stix';
import { INPUT_PARTICIPANT } from '../schema/general';

const reportResolvers = {
  Query: {
    report: (_, { id }, context) => findById(context, context.user, id),
    reports: (_, args, context) => findAll(context, context.user, args),
    reportsTimeSeries: (_, args, context) => {
      if (args.objectId && args.objectId.length > 0) {
        return reportsTimeSeriesByEntity(context, context.user, args);
      }
      if (args.authorId && args.authorId.length > 0) {
        return reportsTimeSeriesByAuthor(context, context.user, args);
      }
      return reportsTimeSeries(context, context.user, args);
    },
    reportsNumber: (_, args, context) => {
      if (args.objectId && args.objectId.length > 0) {
        return reportsNumberByEntity(context, context.user, args);
      }
      if (args.authorId && args.authorId.length > 0) {
        return reportsNumberByAuthor(context, context.user, args);
      }
      return reportsNumber(context, context.user, args);
    },
    reportsDistribution: (_, args, context) => {
      if (args.objectId && args.objectId.length > 0) {
        return reportsDistributionByEntity(context, context.user, args);
      }
      return distributionEntities(context, context.user, [ENTITY_TYPE_CONTAINER_REPORT], args);
    },
    reportContainsStixObjectOrStixRelationship: (_, args, context) => {
      return reportContainsStixObjectOrStixRelationship(context, context.user, args.id, args.stixObjectOrStixRelationshipId);
    },
  },
  Report: {
    deleteWithElementsCount: (report, _, context) => reportDeleteElementsCount(context, context.user, report.id),
    objectParticipant: (container, _, context) => loadThroughDenormalized(context, context.user, container, INPUT_PARTICIPANT, { sortBy: 'user_email' }),
  },
  Mutation: {
    reportEdit: (_, { id }, context) => ({
      delete: ({ purgeElements }) => (purgeElements ? reportDeleteWithElements(context, context.user, id) : stixDomainObjectDelete(context, context.user, id)),
      fieldPatch: ({ input, commitMessage, references }) => stixDomainObjectEditField(context, context.user, id, input, { commitMessage, references }),
      contextPatch: ({ input }) => stixDomainObjectEditContext(context, context.user, id, input),
      contextClean: () => stixDomainObjectCleanContext(context, context.user, id),
      relationAdd: ({ input, commitMessage, references }) => stixDomainObjectAddRelation(context, context.user, id, input, { commitMessage, references }),
      // eslint-disable-next-line max-len
      relationDelete: ({ toId, relationship_type: relationshipType, commitMessage, references }) => stixDomainObjectDeleteRelation(context, context.user, id, toId, relationshipType, { commitMessage, references }),

    }),
    reportAdd: (_, { input }, context) => addReport(context, context.user, input),
  },
};

export default reportResolvers;
