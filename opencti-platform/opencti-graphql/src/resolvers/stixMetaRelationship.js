import { distributionRelations, initBatchLoader } from '../database/middleware';
import stixMetaRelationshipsNumber from '../domain/stixMetaRelationship';
import { elBatchIds } from '../database/elasticSearch';

const loadByIdLoader = initBatchLoader(elBatchIds);

const stixMetaRelationshipResolvers = {
  Query: {
    stixMetaRelationshipsDistribution: (_, args) => distributionRelations(args),
    stixMetaRelationshipsNumber: (_, args) => stixMetaRelationshipsNumber(args),
  },
  StixMetaRelationship: {
    from: (rel) => loadByIdLoader.load(rel.fromId),
    to: (rel) => loadByIdLoader.load(rel.toId),
  },
};

export default stixMetaRelationshipResolvers;
