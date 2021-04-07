import { distributionRelations, batchLoader } from '../database/middleware';
import stixMetaRelationshipsNumber from '../domain/stixMetaRelationship';
import { elBatchIds } from '../database/elasticSearch';

const loadByIdLoader = batchLoader(elBatchIds);

const stixMetaRelationshipResolvers = {
  Query: {
    stixMetaRelationshipsDistribution: (_, args, { user }) => distributionRelations(user, args),
    stixMetaRelationshipsNumber: (_, args, { user }) => stixMetaRelationshipsNumber(user, args),
  },
  StixMetaRelationship: {
    from: (rel, _, { user }) => loadByIdLoader.load(rel.fromId, user),
    to: (rel, _, { user }) => loadByIdLoader.load(rel.toId, user),
  },
};

export default stixMetaRelationshipResolvers;
