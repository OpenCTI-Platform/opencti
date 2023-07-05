import {
  addReport, batchParticipants,
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
import {
  RELATION_CREATED_BY,
  RELATION_OBJECT, RELATION_OBJECT_ASSIGNEE,
  RELATION_OBJECT_LABEL,
  RELATION_OBJECT_MARKING,
} from '../schema/stixRefRelationship';
import { buildRefRelationKey } from '../schema/general';
import { batchLoader, distributionEntities } from '../database/middleware';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../schema/stixDomainObject';

const participantLoader = batchLoader(batchParticipants);

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
    deleteWithElementsCount: (report, args, context) => reportDeleteElementsCount(context, context.user, report.id),
    objectParticipant: (current, _, context) => participantLoader.load(current.id, context, context.user),
  },
  ReportsFilter: {
    createdBy: buildRefRelationKey(RELATION_CREATED_BY),
    markedBy: buildRefRelationKey(RELATION_OBJECT_MARKING),
    assigneeTo: buildRefRelationKey(RELATION_OBJECT_ASSIGNEE),
    labelledBy: buildRefRelationKey(RELATION_OBJECT_LABEL),
    objectContains: buildRefRelationKey(RELATION_OBJECT, '*'),
    creator: 'creator_id',
  },
  Mutation: {
    reportEdit: (_, { id }, context) => ({
      delete: ({ purgeElements }) => (purgeElements ? reportDeleteWithElements(context, context.user, id) : stixDomainObjectDelete(context, context.user, id)),
      fieldPatch: ({ input, commitMessage, references }) => stixDomainObjectEditField(context, context.user, id, input, { commitMessage, references }),
      contextPatch: ({ input }) => stixDomainObjectEditContext(context, context.user, id, input),
      contextClean: () => stixDomainObjectCleanContext(context, context.user, id),
      relationAdd: ({ input }) => stixDomainObjectAddRelation(context, context.user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) => stixDomainObjectDeleteRelation(context, context.user, id, toId, relationshipType),
    }),
    reportAdd: (_, { input }, context) => addReport(context, context.user, input),
  },
};

export default reportResolvers;
