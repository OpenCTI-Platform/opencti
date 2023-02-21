import {
  findAllSystemImplementations,
  findSystemImplementationById,
  createSystemImplementation,
  deleteSystemImplementationById,
  editSystemImplementationById
} from '../domain/informationSystem.js';
  

const cyioSystemImplementationResolvers = {
  Query: {
    // Information System
    systemImplementations: async (_, args, { dbName, dataSources, selectMap }) => findAllSystemImplementations(args, dbName, dataSources, selectMap.getNode('node')),
    systemImplementation: async (_, { id }, { dbName, dataSources, selectMap }) => findSystemImplementationById(id, dbName, dataSources, selectMap.getNode('systemImplementation')),
  },
  Mutation: {
    // Information System
    createSystemImplementation: async (_, { input }, { dbName, dataSources, selectMap }) => createSystemImplementation(input, dbName, dataSources, selectMap),
    deleteSystemImplementation: async (_, { id }, { dbName, dataSources }) => deleteSystemImplementationById( id, dbName, dataSources),
    deleteSystemImplementations: async (_, { ids }, { dbName, dataSources }) => deleteSystemImplementationById( ids, dbName, dataSources),
    editSystemImplementation: async (_, { id, input }, { dbName, dataSources, selectMap }, {schema}) => editSystemImplementationById(id, input, dbName, dataSources, selectMap, schema),
  },
  informationSystem: {
    components: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.components_iris === undefined) return [];
      let results = []
      // for (let iri of parent.components_iris) {
      //   let result = await findComponentsByIri(iri, dbName, dataSources, selectMap.getNode('components'));
      //   if (result === undefined || result === null) return null;
      //   results.push(result);
      // }
      return results;
    },
    inventory_items: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.inventory_items_iris === undefined) return [];
      let results = []
      // for (let iri of parent.inventory_items_iris) {
      //   let result = await findInventoryItemsByIri(iri, dbName, dataSources, selectMap.getNode('inventory_items'));
      //   if (result === undefined || result === null) return null;
      //   results.push(result);
      // }
      return results;
    },
    leveraged_authorizations: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.leveraged_authorizations_iris === undefined) return [];
      let results = []
      // for (let iri of parent.leveraged_authorizations_iris) {
      //   let result = await findLeveragedAuthorizationsByIri(iri, dbName, dataSources, selectMap.getNode('leveraged_authorizations'));
      //   if (result === undefined || result === null) return null;
      //   results.push(result);
      // }
      return results;
    },
    users: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.users_iris === undefined) return [];
      let results = []
      // for (let iri of parent.users_iris) {
      //   let result = await findUsersByIri(iri, dbName, dataSources, selectMap.getNode('user'));
      //   if (result === undefined || result === null) return null;
      //   results.push(result);
      // }
      return results;
    },
    labels: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.labels_iris === undefined) return [];
    },
    links: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.links_iris === undefined) return [];
    },
    remarks: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.remarks_iris === undefined) return [];
    },
  },
};

export default cyioSystemImplementationResolvers;
