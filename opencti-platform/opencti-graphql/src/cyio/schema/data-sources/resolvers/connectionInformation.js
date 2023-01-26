import {
  findAllConnectionConfig,
  findConnectionConfigById,
  createConnectionConfig,
  deleteConnectionConfigById,
  editConnectionConfigById,
} from '../domain/connectionInformation.js';

const cyioConnectionInformationResolvers = {
  Query: {
    connectionConfigs: async (_, args, { dbName, dataSources, selectMap }) =>
      findAllConnectionConfig(args, dbName, dataSources, selectMap),
    connectionConfig: async (_, { id }, { dbName, dataSources, selectMap }) =>
      findConnectionConfigById(id, dbName, dataSources, selectMap),
  },
  Mutation: {
    createConnectionConfig: async (_, { input }, { dbName, selectMap, dataSources }) =>
      createConnectionConfig(input, dbName, selectMap, dataSources),
    deleteConnectionConfig: async (_, { id }, { dbName, dataSources }) =>
      deleteConnectionConfigById(id, dbName, dataSources),
    deleteConnectionConfigs: async (_, { ids }, { dbName, dataSources }) =>
      deleteConnectionConfigById(ids, dbName, dataSources),
    editConnectionConfig: async (_, { id, input }, { dbName, dataSources, selectMap }, { schema }) =>
      editConnectionConfigById(id, input, dbName, dataSources, selectMap, schema),
  },
};

export default cyioConnectionInformationResolvers;
