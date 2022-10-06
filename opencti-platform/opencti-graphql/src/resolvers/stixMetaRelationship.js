import { distributionRelations, batchLoader } from '../database/middleware';
import { findAll, findById, stixMetaRelationshipsNumber } from '../domain/stixMetaRelationship';
import { elBatchIds } from '../database/engine';

const loadByIdLoader = batchLoader(elBatchIds);

const stixMetaRelationshipResolvers = {
  Query: {
    stixMetaRelationship: (_, { id }, context) => findById(context, context.user, id),
    stixMetaRelationships: (_, args, context) => findAll(context, context.user, args),
    stixMetaRelationshipsDistribution: (_, args, context) => distributionRelations(context, context.user, args),
    stixMetaRelationshipsNumber: (_, args, context) => stixMetaRelationshipsNumber(context, context.user, args),
  },
  StixMetaRelationship: {
    from: (rel, _, context) => loadByIdLoader.load(rel.fromId, context, context.user),
    to: (rel, _, context) => loadByIdLoader.load(rel.toId, context, context.user),
  },
};

export default stixMetaRelationshipResolvers;
