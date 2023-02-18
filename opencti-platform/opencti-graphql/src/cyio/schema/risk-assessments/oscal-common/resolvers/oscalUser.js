import {
  findAllOscalUsers,
  findOscalUserById,
  createOscalUser,
  deleteOscalUserById,
  editOscalUserById,
  attachToOscalUser,
  detachFromOscalUser,
} from '../domain/oscalUser';


const cyioOscalUserResolvers = {
  Query: {
    // Oscal User
		oscalUsers: async (_, args, { dbName, dataSources, selectMap }) => findAllOscalUsers(args, dbName, dataSources, selectMap.getNode('node')),
		oscalUser: async (_, { id }, { dbName, dataSources, selectMap }) => findOscalUserById(id, dbName, dataSources, selectMap.getNode('oscalUser')),
  },
  Mutation: {
		createOscalUser: async (_, { input }, { dbName, selectMap, dataSources }) => createOscalUser(input, dbName, dataSources, selectMap.get("createOscalUser")),
		deleteOscalUser: async (_, { id }, { dbName, dataSources }) => deleteOscalUserById( id, dbName, dataSources),
		deleteOscalUsers: async (_, { ids }, { dbName, dataSources }) => deleteOscalUserById( ids, dbName, dataSources),
		editOscalUser: async (_, { id, input }, { dbName, dataSources, selectMap }, {schema}) => editOscalUserById(id, input, dbName, dataSources, selectMap.getNode("editOscalUser"), schema),
		attachToOscalUser: async (_, { id, field, entityId }, { dbName, dataSources }) => attachToOscalUser(id, field, entityId ,dbName, dataSources),
		detachFromOscalUser: async (_, { id, field, entityId }, { dbName, dataSources }) => detachFromOscalUser(id, field, entityId ,dbName, dataSources),
  },
  oscalUser: {
    roles: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.role_iris === undefined) return [];
      let results = []
      for (let iri of parent.role_iris) {
        let result = await findRoleByIri(iri, dbName, dataSources, selectMap.getNode('information_types'));
        if (result === undefined || result === null) return null;
        results.push(result);
      }
      return results;
    },
    authorized_privileges: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.authorized_privilege_iris === undefined) return [];
      let results = []
      for (let iri of parent.authorized_privilege_iris) {
        let result = await findAuthorizedPrivilegeByIri(iri, dbName, dataSources, selectMap.getNode('information_types'));
        if (result === undefined || result === null) return null;
        results.push(result);
      }
      return results;
    },
    labels: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.label_iris === undefined) return [];
      let results = []
      for (let iri of parent.label_iris) {
        let result = await findLabelByIri(iri, dbName, dataSources, selectMap.getNode('information_types'));
        if (result === undefined || result === null) return null;
        results.push(result);
      }
      return results;
    },
    links: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.link_iris === undefined) return [];
      let results = []
      for (let iri of parent.link_iris) {
        let result = await findLinkByIri(iri, dbName, dataSources, selectMap.getNode('information_types'));
        if (result === undefined || result === null) return null;
        results.push(result);
      }
      return results;
    },
    remarks: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.remark_iris === undefined) return [];
      let results = []
      for (let iri of parent.remark_iris) {
        let result = await findRemarkByIri(iri, dbName, dataSources, selectMap.getNode('information_types'));
        if (result === undefined || result === null) return null;
        results.push(result);
      }
      return results;
    },
  }
};

export default cyioOscalUserResolvers;
