import { storeLoadById } from '../database/middleware-loader';

const internalRelationshipResolvers = {
  InternalRelationship: {
    from: (rel, _, context) => storeLoadById(context, context.user, rel.fromId, rel.fromType),
    to: (rel, _, context) => storeLoadById(context, context.user, rel.toId, rel.toType),
  },
};

export default internalRelationshipResolvers;
