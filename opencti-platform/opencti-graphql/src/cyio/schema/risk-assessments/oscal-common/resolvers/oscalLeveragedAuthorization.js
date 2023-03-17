import {
  findAllLeveragedAuthorizations,
  findLeveragedAuthorizationById,
  createLeveragedAuthorization,
  deleteLeveragedAuthorizationById,
  editLeveragedAuthorizationById,
  attachToLeveragedAuthorization,
  detachFromLeveragedAuthorization,
} from '../domain/oscalLeveragedAuthorization';
import { findDataMarkingByIri } from '../../../data-markings/domain/dataMarkings.js';
import { findLabelByIri } from '../../../global/domain/label.js';
import { findPartyByIri } from '../domain/oscalParty.js';
import { findLinkByIri } from '../domain/oscalLink.js';
import { findRemarkByIri } from '../domain/oscalRemark.js';


const cyioOscalLeveragedAuthorizationResolvers = {
  Query: {
    // Oscal User
        leveragedAuthorizations: async (_, args, { dbName, dataSources, selectMap }) => findAllLeveragedAuthorizations(args, dbName, dataSources, selectMap.getNode('node')),
        leveragedAuthorization: async (_, { id }, { dbName, dataSources, selectMap }) => findLeveragedAuthorizationById(id, dbName, dataSources, selectMap.getNode('leveragedAuthorization')),
  },
  Mutation: {
        createLeveragedAuthorization: async (_, { input }, { dbName, selectMap, dataSources }) => createLeveragedAuthorization(input, dbName, dataSources, selectMap.getNode("createLeveragedAuthorization")),
        deleteLeveragedAuthorization: async (_, { id }, { dbName, dataSources }) => deleteLeveragedAuthorizationById( id, dbName, dataSources),
        deleteLeveragedAuthorizations: async (_, { ids }, { dbName, dataSources }) => deleteLeveragedAuthorizationById( ids, dbName, dataSources),
        editLeveragedAuthorization: async (_, { id, input }, { dbName, dataSources, selectMap }, {schema}) => editLeveragedAuthorizationById(id, input, dbName, dataSources, selectMap.getNode("editLeveragedAuthorization"), schema),
        attachToLeveragedAuthorization: async (_, { id, field, entityId }, { dbName, dataSources }) => attachToLeveragedAuthorization(id, field, entityId ,dbName, dataSources),
        detachFromLeveragedAuthorization: async (_, { id, field, entityId }, { dbName, dataSources }) => detachFromLeveragedAuthorization(id, field, entityId ,dbName, dataSources),
  },
  OscalLeveragedAuthorization: {
    party: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.party_iri === undefined) return [];
      let result = await findPartyByIri(parent.party_iri, dbName, dataSources, selectMap.getNode('party'));
      if (result === undefined || result === null) return null;
      return result;
    },
    object_markings: async (parent, _, { dbName, dataSources, selectMap}) => {
      if (parent.marking_iris === undefined) return [];
      let results = []
      for (let iri of parent.marking_iris) {
        let result = await findDataMarkingByIri(iri, dbName, dataSources, selectMap.getNode('object_markings'));
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

export default cyioOscalLeveragedAuthorizationResolvers;
  