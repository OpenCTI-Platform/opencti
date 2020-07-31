import { loadById } from '../database/grakn';

const internalRelationshipResolvers = {
  InternalRelationship: {
    from: (rel) => loadById(rel.fromId, rel.fromType),
    to: (rel) => loadById(rel.toId, rel.toType),
  },
};

export default internalRelationshipResolvers;
