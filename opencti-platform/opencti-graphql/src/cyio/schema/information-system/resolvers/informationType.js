import conf from '../../../../config/conf';
import {
  findAllInformationTypes,
  findInformationTypeById,
  findInformationTypeByIri,
  createInformationType,
  deleteInformationTypeById,
  editInformationTypeById,
  attachToInformationType,
  detachFromInformationType,
  // 
  findAllImpactDefinitions,
  findImpactDefinitionById,
  findImpactDefinitionByIri,
  createImpactDefinition,
  deleteImpactDefinitionById,
  editImpactDefinitionById,
  // 
  findAllCategorizations,
  findCategorizationById,
  findCategorizationByIri,
  createCategorization,
  deleteCategorizationById,
  editCategorizationById,
  attachToCategorization,
  detachFromCategorization,
} from '../domain/informationType.js';

const cyioInformationTypeResolvers = {
  Query: {
    // Information System
    informationTypes: async (_, args, { dbName, dataSources, selectMap }) => findAllInformationTypes(args, dbName, dataSources, selectMap.getNode('node')),
    informationType: async (_, { id }, { dbName, dataSources, selectMap }) => findInformationTypeById(id, dbName, dataSources, selectMap.getNode('informationType')),
    // Impact Definition
    impactDefinitions: async (_, args, { dbName, dataSources, selectMap }) => findAllImpactDefinitions(args, dbName, dataSources, selectMap.getNode('node')),
    impactDefinition: async (_, { id }, { dbName, dataSources, selectMap }) => findImpactDefinitionById(id, dbName, dataSources, selectMap.getNode('impactDefinition')),
    // Categorizations
    categorizations: async (_, args, { dbName, dataSources, selectMap }) => findAllCategorizations(args, dbName, dataSources, selectMap.getNode('node')),
    categorization: async (_, { id }, { dbName, dataSources, selectMap }) => findCategorizationById(id, dbName, dataSources, selectMap.getNode('categorization')),
  },
  Mutation: {
    // Information System
    createInformationType: async (_, { input }, { dbName, selectMap, dataSources }) => createInformationType(input, dbName, dataSources, selectMap.getNode("createInformationType")),
    deleteInformationType: async (_, { id }, { dbName, dataSources }) => deleteInformationTypeById( id, dbName, dataSources),
    deleteInformationTypes: async (_, { ids }, { dbName, dataSources }) => deleteInformationTypeById( ids, dbName, dataSources),
    editInformationType: async (_, { id, input }, { dbName, dataSources, selectMap }, {schema}) => editInformationTypeById(id, input, dbName, dataSources, selectMap.getNode("editInformationType"), schema),
    attachToInformationType: async (_, { id, field, entryId }, { dbName, dataSources }) => attachToInformationType(id, field, entryId ,dbName, dataSources),
    detachFromInformationType: async (_, { id, field, entryId }, { dbName, dataSources }) => detachFromInformationType(id, field, entryId ,dbName, dataSources),
    // Impact Definition
    createImpactDefinition: async (_, { input }, { dbName, selectMap, dataSources }) => createImpactDefinition(input, dbName, dataSources, selectMap.getNode("createImpactDefinition")),
    deleteImpactDefinition: async (_, { id }, { dbName, dataSources }) => deleteImpactDefinitionById( id, dbName, dataSources),
    deleteImpactDefinitions: async (_, { ids }, { dbName, dataSources }) => deleteImpactDefinitionById( ids, dbName, dataSources),
    editImpactDefinition: async (_, { id, input }, { dbName, dataSources, selectMap }, {schema}) => editImpactDefinitionById(id, input, dbName, dataSources, selectMap.getNode("editImpactDefinition"), schema),
    // Categorization
    createCategorization: async (_, { input }, { dbName, selectMap, dataSources }) => createCategorization(input, dbName, dataSources, selectMap.getNode("createCategorization")),
    deleteCategorization: async (_, { id }, { dbName, dataSources }) => deleteCategorizationById( id, dbName, dataSources),
    deleteCategorizations: async (_, { ids }, { dbName, dataSources }) => deleteCategorizationById( ids, dbName, dataSources),
    editCategorization: async (_, { id, input }, { dbName, dataSources, selectMap }, {schema}) => editCategorizationById(id, input, dbName, dataSources, selectMap.getNode("editCategorization"), schema),
    attachToCategorization: async (_, { id, field, entryId }, { dbName, dataSources }) => attachToCategorization(id, field, entryId ,dbName, dataSources),
    detachFromCategorization: async (_, { id, field, entryId }, { dbName, dataSources }) => detachFromCategorization(id, field, entryId ,dbName, dataSources),
  },
  InformationType: {
    categorizations: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.categorization_iris === undefined) return [];
      let results = []
      for (let iri of parent.categorization_iris) {
        let result = findCategorizationByIri(iri, dbName, dataSources, selectMap.getNode('categorizations'));
        if (result === undefined || result === null) return null;
        results.push(result)
      }
      return results;
		},
		confidentiality_impact: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.confidentiality_impact_iri === undefined) return null;

      // if information type contained within a catalog, change database to contextual memory
      if ( parent.hasOwnProperty('system') && parent.hasOwnProperty('category') && parent.hasOwnProperty('identifier')) {
        dbName = conf.get('app:database:context') || 'cyber-context';
      }

      let impact = findImpactDefinitionByIri(parent.confidentiality_impact_iri, dbName, dataSources, selectMap.getNode('confidentiality_impact'));
      if (impact === undefined || impact === null) return null;
      return impact;
		},
		integrity_impact: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.integrity_impact_iri === undefined) return null;

      // if information type contained within a catalog, change database to contextual memory
      if ( parent.hasOwnProperty('system') && parent.hasOwnProperty('category') && parent.hasOwnProperty('identifier')) {
        dbName = conf.get('app:database:context') || 'cyber-context';
      }

      let impact = findImpactDefinitionByIri(parent.integrity_impact_iri, dbName, dataSources, selectMap.getNode('integrity_impact'));
      if (impact === undefined || impact === null) return null;
      return impact;
		},
		availability_impact: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.availability_impact_iri === undefined) return null;

      // if information type contained within a catalog, change database to contextual memory
      if ( parent.hasOwnProperty('system') && parent.hasOwnProperty('category') && parent.hasOwnProperty('identifier')) {
        dbName = conf.get('app:database:context') || 'cyber-context';
      }

      let impact = findImpactDefinitionByIri(parent.availability_impact_iri, dbName, dataSources, selectMap.getNode('availability_impact'));
      if (impact === undefined || impact === null) return null;
      return impact;
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
	},
  Categorization: {
    information_type: async (parent, _, { dataSources, selectMap }) => {
      if (parent.information_type_iri === undefined) return null;
      let dbName = conf.get('app:database:context') || 'cyber-context';
      let infoType = findInformationTypeByIri(parent.information_type_iri, dbName, dataSources, selectMap.getNode('information_type'));
      if (infoType === undefined || infoType === null) return null;
      return infoType;
    },
  },
  // Map enum GraphQL values to data model required values
  FIPS199: {
    fips_199_low: 'fips-199-low',
    fips_199_moderate: 'fips-199-moderate',
    fips_199_high: 'fips-199-high',
  },
};

export default cyioInformationTypeResolvers;
