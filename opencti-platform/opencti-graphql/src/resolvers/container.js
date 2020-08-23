import { findAll, findById, objects } from "../domain/container";

const containerResolvers = {
  Query: {
    container: (_, { id }) => findById(id),
    containers: (_, args) => findAll(args),
  },
  Container: {
    objects: (container, args) => objects(container.id, args),
  },
};

export default containerResolvers;
