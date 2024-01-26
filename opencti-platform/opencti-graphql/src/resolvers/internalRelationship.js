import { batchLoader } from '../database/middleware';
import { elBatchIds } from '../database/engine';

const loadByIdLoader = batchLoader(elBatchIds);

const internalRelationshipResolvers = {
  InternalRelationship: {
    from: (rel, _, context) => (rel.from ? rel.from : loadByIdLoader.load({ id: rel.fromId, type: rel.fromType }, context, context.user)),
    to: (rel, _, context) => (rel.to ? rel.to : loadByIdLoader.load({ id: rel.toId, type: rel.toType }, context, context.user)),
  },
};

export default internalRelationshipResolvers;
