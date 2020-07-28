import { loadById } from '../database/grakn';

const stixMetaRelationshipResolvers = {
  StixMetaRelationship: {
    from: (rel) => loadById(rel.fromId, rel.fromType),
    to: (rel) => loadById(rel.toId, rel.toType),
  },
};

export default stixMetaRelationshipResolvers;
