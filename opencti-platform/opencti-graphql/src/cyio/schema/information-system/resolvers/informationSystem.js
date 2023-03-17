import {
  findAllInformationSystems,
  findInformationSystemById,
  createInformationSystem,
  deleteInformationSystemById,
  editInformationSystemById,
  attachToInformationSystem,
  detachFromInformationSystem,
  getInformationSystemSecurityStatus,
  addImplementationEntity,
  removeImplementationEntity,
  findSystemImplementation,
  findObjects,
} from '../domain/informationSystem.js';
import { findDescriptionBlockByIri } from '../domain/descriptionBlock.js';
import { findInformationTypeByIri } from '../domain/informationType.js';
import { findDataMarkingByIri } from '../../data-markings/domain/dataMarkings.js';


const cyioInformationSystemResolvers = {
  Query: {
    // Information System
    informationSystems: async (_, args, { user, token, kauth, clientId, dbName, dataSources, selectMap }) => findAllInformationSystems(args, dbName, dataSources, selectMap.getNode('node')),
    informationSystem: async (_, { id }, { user, token, kauth, clientId, dbName, dataSources, selectMap }) => findInformationSystemById(id, dbName, dataSources, selectMap.getNode('informationSystem')),
    informationSystemSecurityStatus: async (_, { id }, {dbName, dataSources, selectMap }) => getInformationSystemSecurityStatus( id,dbName, dataSources, selectMap.getNode('node')),
  },
  Mutation: {
    // Information System
    createInformationSystem: async (_, { input }, { dbName, dataSources, selectMap }) => createInformationSystem(input, dbName, dataSources, selectMap.getNode("createInformationSystem")),
    deleteInformationSystem: async (_, { id }, { dbName, dataSources }) => deleteInformationSystemById( id, dbName, dataSources),
    deleteInformationSystems: async (_, { ids }, { dbName, dataSources }) => deleteInformationSystemById( ids, dbName, dataSources),
    editInformationSystem: async (_, { id, input }, { dbName, dataSources, selectMap }, {schema}) => editInformationSystemById(id, input, dbName, dataSources, selectMap.getNode("editInformationSystem"), schema),
    // Attach and Detach
    attachToInformationSystem: async (_, { id, field, entityId }, { dbName, dataSources }) => attachToInformationSystem(id, field, entityId ,dbName, dataSources),
    detachFromInformationSystem: async (_, { id, field, entityId }, { dbName, dataSources }) => detachFromInformationSystem(id, field, entityId ,dbName, dataSources),
    // Implementation items
    addInformationSystemImplementationEntity: async (_, { id, implementation_type, entityId }, { dbName, dataSources }) => addImplementationEntity(id, implementation_type, entityId, dbName, dataSources),
    removeInformationSystemImplementationEntity: async (_, { id, implementation_type, entityId }, { dbName, dataSources }) => removeImplementationEntity(id, implementation_type, entityId, dbName, dataSources),
  },
  InformationSystem: {
    authorization_boundary: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.authorization_boundary_iri === undefined) return null;
      let result = await findDescriptionBlockByIri(parent.authorization_boundary_iri, dbName, dataSources, selectMap.getNode('authorization_boundary'));
      if (result === undefined || result === null) return null;
      return result;
    },
    network_architecture: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.network_architecture_iri === undefined) return null;
      let result = await findDescriptionBlockByIri(parent.network_architecture_iri, dbName, dataSources, selectMap.getNode('network_architecture'));
      if (result === undefined || result === null) return null;
      return result;
    },
    data_flow: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.data_flow_iri === undefined) return null;
      let result = await findDescriptionBlockByIri(parent.data_flow_iri, dbName, dataSources, selectMap.getNode('data_flow'));
      if (result === undefined || result === null) return null;
      return result;
    },
    information_types: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.information_type_iris === undefined) return [];
      let results = []
      for (let iri of parent.information_types_iris) {
        let result = await findInformationTypeByIri(iri, dbName, dataSources, selectMap.getNode('information_types'));
        if (result === undefined || result === null) return null;
        results.push(result);
      }
      return results;
    },
    system_implementation: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.component_iris === undefined && 
          parent.inventory_item_iris === undefined &&
          parent.leveraged_authorization_iris === undefined && 
          parent.user_type_iris === undefined ) return null;

      let systemImplementation = await findSystemImplementation(parent, dbName, dataSources, selectMap);
      if (systemImplementation === undefined || systemImplementation === null) return null;
      return systemImplementation;
    },
    objects: async (parent, args, { dbName, dataSources, selectMap }) => {
      if (parent.information_types === undefined &&
          parent.component_iris === undefined && 
          parent.inventory_item_iris === undefined &&
          parent.leveraged_authorization_iris === undefined && 
          parent.user_type_iris === undefined ) return null;

      let objects = await findObjects(parent, dbName, dataSources, selectMap);
      if (objects === undefined || objects === null) return null;
      return objects;
    },
    responsible_parties: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.responsible_party_iris === undefined) return [];
      let results = []
      for (let iri of parent.responsible_party_iris) {
        let result = await findResponsiblePartyByIri(iri, dbName, dataSources, selectMap.getNode('responsible_parties'));
        if (result === undefined || result === null) continue;
        results.push(result);
      }
      return results;
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
  },
  ObjectRef: {
    __resolveType: (item) => {
      if (item.entity_type === 'component') return 'Component';
      if (item.entity_type === 'inventory-item') return 'InventoryItem';
      if (item.entity_type === 'information-system') return 'InformationSystem';
      if (item.entity_type === 'oscal-user') return 'OscalUser';
      if (item.entity_type === 'oscal-leveraged-authorization') return 'OscalLeveragedAuthorization';
      if (item.entity_type === 'oscal-relationship') return 'OscalRelationship';
    }
  },
  // Map enum GraphQL values to data model required values
  DeploymentModelType: {
    public_cloud: "public-cloud",
    private_cloud: "private-cloud",
    community_cloud: "community-cloud",
    government_only_cloud: "government-only-cloud",
    on_premise: "on-premise",
    other: "other"
  },
  FIPS199: {
    fips_199_low: 'fips-199-low',
    fips_199_moderate: 'fips-199-moderate',
    fips_199_high: 'fips-199-high',
  }
};

export default cyioInformationSystemResolvers;
