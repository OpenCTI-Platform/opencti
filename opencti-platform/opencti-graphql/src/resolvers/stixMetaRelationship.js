import { distributionRelations, loadById } from '../database/middleware';
import stixMetaRelationshipsNumber from '../domain/stixMetaRelationship';

const stixMetaRelationshipResolvers = {
  Query: {
    stixMetaRelationshipsDistribution: (_, args) => distributionRelations(args),
    stixMetaRelationshipsNumber: (_, args) => stixMetaRelationshipsNumber(args),
  },
  StixMetaRelationship: {
    from: (rel) => loadById(rel.fromId, rel.fromType),
    to: (rel) => loadById(rel.toId, rel.toType),
  },
};

export default stixMetaRelationshipResolvers;
