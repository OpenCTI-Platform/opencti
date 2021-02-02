import { loadById } from '../database/middleware';

const internalRelationshipResolvers = {
  InternalRelationship: {
    from: (rel, _, { user }) => loadById(user, rel.fromId, rel.fromType),
    to: (rel, _, { user }) => loadById(user, rel.toId, rel.toType),
  },
};

export default internalRelationshipResolvers;
