import { distributionRelations, batchLoader } from '../database/middleware';
import { findAll, findById, stixMetaRelationshipsNumber } from '../domain/stixMetaRelationship';
import { elBatchIds } from '../database/engine';

const loadByIdLoader = batchLoader(elBatchIds);

const stixMetaRelationshipResolvers = {
  Query: {
    stixMetaRelationship: (_, { id }, { user }) => findById(user, id),
    stixMetaRelationships: (_, args, { user }) => findAll(user, args),
    stixMetaRelationshipsDistribution: (_, args, { user }) => distributionRelations(user, args),
    stixMetaRelationshipsNumber: (_, args, { user }) => stixMetaRelationshipsNumber(user, args),
  },
  StixMetaRelationship: {
    from: (rel, _, { user }) => loadByIdLoader.load(rel.fromId, user),
    to: (rel, _, { user }) => loadByIdLoader.load(rel.toId, user),
  },
};

export default stixMetaRelationshipResolvers;
