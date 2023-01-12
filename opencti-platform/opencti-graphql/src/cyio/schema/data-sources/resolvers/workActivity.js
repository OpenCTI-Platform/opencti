import {
  // findAllWorkActivity,
  // findWorkActivityById,
  // createWorkActivity,
  // deleteWorkActivityById,
  // editWorkActivityById,
  findAllIngestActivities,
  findIngestActivityById,
  findSourceActivityById,
  findActivityMessagesById,
  findActivityErrorsById,
  findActivityTrackingById,
  findInitiatorById,
} from '../domain/workActivity.js';

const cyioWorkActivityResolvers = {
  Query: {
    ingestActivities: async (_, args, { dataSources }) => findAllIngestActivities(args, dataSources),
    ingestActivity: async (_, { id, activityId }, { dataSources }) => findIngestActivityById(id, activityId, dataSources),
    sourceIngestActivity: async (_, { sourceId }, { dataSources }) => findSourceActivityById(sourceId, dataSources),
  },
  
  // Mutation: {
  // },

  // IngestActivity: {
  //   messages: async (parent, _, { dbName, dataSources, selectMap}) => {
  //     if (parent.message_ids === undefined) return [];
  //     return findActivityMessagesById(parent, dbName, dataSources, selectMap);
  //   },
  //   errors: async (parent, _, { dbName, dataSources, selectMap }) => {
  //     if (parent.error_ids === undefined) return [];
  //     return findActivityErrorsById(parent, dbName, dataSources, selectMap);
  //   },
  //   tracking: async (parent, _, { dbName, dataSources, selectMap }) => {
  //     if (parent.tracking_ids === undefined) return null;
  //     return findActivityTrackingById(parent, dbName, dataSources, selectMap);
  //   },
  //   initiator: async (parent, _, { dbName, dataSources, selectMap }) => {
  //       if (parent.initiator_iri === undefined) return null;
  //       return findInitiatorById(parent, dbName, dataSources, selectMap);
  //   },
  // },
};

export default cyioWorkActivityResolvers;