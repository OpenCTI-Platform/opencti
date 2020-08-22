import { distributionRelations, loadById } from '../database/grakn';

const stixMetaRelationshipResolvers = {
  Query: {
    stixMetaRelationshipsDistribution: (_, args) => distributionRelations(args),
  },
  StixMetaRelationship: {
    from: (rel) => loadById(rel.fromId, rel.fromType),
    to: (rel) => loadById(rel.toId, rel.toType),
  },
};

export default stixMetaRelationshipResolvers;
