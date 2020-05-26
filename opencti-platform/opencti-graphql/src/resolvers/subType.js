import { findAll } from '../domain/subType';

const subTypeResolvers = {
  Query: {
    subTypes: (_, args) => findAll(args),
  },
};

export default subTypeResolvers;
