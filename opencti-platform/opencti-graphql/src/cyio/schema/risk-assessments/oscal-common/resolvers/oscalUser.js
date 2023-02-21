import {
  findAllUserTypes,
  findUserTypeById,
  createUserType,
  deleteUserTypeById,
  editUserTypeById,
  attachToUserType,
  detachFromUserType,
  findAllAuthorizedPrivilegeEntries,
  findAuthorizedPrivilegeById,
  findAuthorizedPrivilegeByIri,
  createAuthorizedPrivilege,
  deleteAuthorizedPrivilegeById,
  editAuthorizedPrivilegeById,
  attachToAuthorizedPrivilege,
  detachFromAuthorizedPrivilege,
} from '../domain/oscalUser';
import { findLabelByIri } from '../../../global/domain/label.js';
import { findRoleByIri } from '../domain/oscalRole.js';
import { findLinkByIri } from '../domain/oscalLink.js';
import { findRemarkByIri } from '../domain/oscalRemark.js';


const cyioOscalUserResolvers = {
  Query: {
    // Oscal User
		oscalUsers: async (_, args, { dbName, dataSources, selectMap }) => findAllUserTypes(args, dbName, dataSources, selectMap.getNode('node')),
		oscalUser: async (_, { id }, { dbName, dataSources, selectMap }) => findUserTypeById(id, dbName, dataSources, selectMap.getNode('oscalUser')),
    // Authorized Privilege
    authorizedPrivileges: async (_, args, { dbName, dataSources, selectMap }) => findAllAuthorizedPrivilegeEntries(args, dbName, dataSources, selectMap.getNode('node')),
    authorizedPrivilege: async (_, { id }, { dbName, dataSources, selectMap }) => findAuthorizedPrivilegeById(id, dbName, dataSources, selectMap.getNode('authorizedPrivilege')),
  },
  Mutation: {
    // Oscal User
		createOscalUser: async (_, { input }, { dbName, selectMap, dataSources }) => createUserType(input, dbName, dataSources, selectMap.getNode("createOscalUser")),
		deleteOscalUser: async (_, { id }, { dbName, dataSources }) => deleteUserTypeById( id, dbName, dataSources),
		deleteOscalUsers: async (_, { ids }, { dbName, dataSources }) => deleteUserTypeById( ids, dbName, dataSources),
		editOscalUser: async (_, { id, input }, { dbName, dataSources, selectMap }, {schema}) => editUserTypeById(id, input, dbName, dataSources, selectMap.getNode("editOscalUser"), schema),
		attachToOscalUser: async (_, { id, field, entityId }, { dbName, dataSources }) => attachToUserType(id, field, entityId ,dbName, dataSources),
		detachFromOscalUser: async (_, { id, field, entityId }, { dbName, dataSources }) => detachFromUserType(id, field, entityId ,dbName, dataSources),
    // Authorized Privilege
		createAuthorizedPrivilege: async (_, { input }, { dbName, selectMap, dataSources }) => createAuthorizedPrivilege(input, dbName, dataSources, selectMap.getNode("createAuthorizedPrivilege")),
		deleteAuthorizedPrivilege: async (_, { id }, { dbName, dataSources }) => deleteAuthorizedPrivilegeById( id, dbName, dataSources),
		deleteAuthorizedPrivileges: async (_, { ids }, { dbName, dataSources }) => deleteAuthorizedPrivilegeById( ids, dbName, dataSources),
		editAuthorizedPrivilege: async (_, { id, input }, { dbName, dataSources, selectMap }, {schema}) => editAuthorizedPrivilegeById(id, input, dbName, dataSources, selectMap.getNode("editAuthorizedPrivilege"), schema),
		attachToAuthorizedPrivilege: async (_, { id, field, entityId }, { dbName, dataSources }) => attachToAuthorizedPrivilege(id, field, entityId ,dbName, dataSources),
		detachFromAuthorizedPrivilege: async (_, { id, field, entityId }, { dbName, dataSources }) => detachFromAuthorizedPrivilege(id, field, entityId ,dbName, dataSources),

  },
  OscalUser: {
    roles: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.role_iris === undefined) return [];
      let results = []
      for (let iri of parent.role_iris) {
        let result = await findRoleByIri(iri, dbName, dataSources, selectMap.getNode('roles'));
        if (result === undefined || result === null) return null;
        results.push(result);
      }
      return results;
    },
    authorized_privileges: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.authorized_privilege_iris === undefined) return [];
      let results = []
      for (let iri of parent.authorized_privilege_iris) {
        let result = await findAuthorizedPrivilegeByIri(iri, dbName, dataSources, selectMap.getNode('authorized_privileges'));
        if (result === undefined || result === null) return null;
        results.push(result);
      }
      return results;
    },
    labels: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.label_iris === undefined) return [];
      let results = []
      for (let iri of parent.label_iris) {
        let result = await findLabelByIri(iri, dbName, dataSources, selectMap.getNode('labels'));
        if (result === undefined || result === null) return null;
        results.push(result);
      }
      return results;
    },
    links: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.link_iris === undefined) return [];
      let results = []
      for (let iri of parent.link_iris) {
        let result = await findLinkByIri(iri, dbName, dataSources, selectMap.getNode('links'));
        if (result === undefined || result === null) return null;
        results.push(result);
      }
      return results;
    },
    remarks: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.remark_iris === undefined) return [];
      let results = []
      for (let iri of parent.remark_iris) {
        let result = await findRemarkByIri(iri, dbName, dataSources, selectMap.getNode('remarks'));
        if (result === undefined || result === null) return null;
        results.push(result);
      }
      return results;
    },
  }
};

export default cyioOscalUserResolvers;
