import { storeLoadById } from '../database/middleware';

const internalRelationshipResolvers = {
  InternalRelationship: {
    from: (rel, _, { user }) => storeLoadById(user, rel.fromId, rel.fromType),
    to: (rel, _, { user }) => storeLoadById(user, rel.toId, rel.toType),
  },
};

export default internalRelationshipResolvers;
