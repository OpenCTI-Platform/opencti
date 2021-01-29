import { distributionRelations, initBatchLoader } from '../database/middleware';
import stixMetaRelationshipsNumber from '../domain/stixMetaRelationship';
import { elBatchIds } from '../database/elasticSearch';

const loadByIdLoader = (user) => initBatchLoader(user, elBatchIds);

const stixMetaRelationshipResolvers = {
  Query: {
    stixMetaRelationshipsDistribution: (_, args, { user }) => distributionRelations(user, args),
    stixMetaRelationshipsNumber: (_, args, { user }) => stixMetaRelationshipsNumber(user, args),
  },
  StixMetaRelationship: {
    from: (rel, _, { user }) => loadByIdLoader(user).load(rel.fromId),
    to: (rel, _, { user }) => loadByIdLoader(user).load(rel.toId),
  },
};

export default stixMetaRelationshipResolvers;
