const internalRelationshipResolvers = {
  InternalRelationship: {
    from: (rel, _, context) => (rel.from ? rel.from : context.batch.idsBatchLoader.load({ id: rel.fromId, type: rel.fromType })),
    to: (rel, _, context) => (rel.to ? rel.to : context.batch.idsBatchLoader.load({ id: rel.toId, type: rel.toType })),
  },
};

export default internalRelationshipResolvers;
