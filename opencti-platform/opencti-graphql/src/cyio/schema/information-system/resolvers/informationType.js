import conf from '../../../../config/conf';
import {
  findAllInformationTypes,
  findInformationTypeById,
  createInformationType,
  deleteInformationTypeById,
  editInformationTypeById,
  findImpactDefinitionByIri,
  findCategorizationByIri,
} from '../domain/informationType.js';

const cyioInformationTypeResolvers = {
  Query: {
    // Information System
    informationTypes: async (_, args, { dbName, dataSources, selectMap }) => findAllInformationTypes(args, dbName, dataSources, selectMap.getNode('node')),
    informationType: async (_, { id }, { dbName, dataSources, selectMap }) => findInformationTypeById(id, dbName, dataSources, selectMap.getNode('informationType')),
  },
  Mutation: {
    // Information System
    createInformationType: async (_, { input }, { dbName, selectMap, dataSources }) => createInformationType(input, dbName, dataSources, selectMap.getNode("createInformationType")),
    deleteInformationType: async (_, { id }, { dbName, dataSources }) => deleteInformationTypeById( id, dbName, dataSources),
    deleteInformationTypes: async (_, { ids }, { dbName, dataSources }) => deleteInformationTypeById( ids, dbName, dataSources),
    editInformationType: async (_, { id, input }, { dbName, dataSources, selectMap }, {schema}) => editInformationTypeById(id, input, dbName, dataSources, selectMap.getNode("editInformationType"), schema),
    attachToInformationType: async (_, { id, field, entryId }, { dbName, dataSources }) => attachToInformationType(id, field, entryId ,dbName, dataSources),
    detachFromInformationType: async (_, { id, field, entryId }, { dbName, dataSources }) => detachFromInformationType(id, field, entryId ,dbName, dataSources),
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
  // Map enum GraphQL values to data model required values
  FIPS199: {
    fips_199_low: 'fips-199-low',
    fips_199_moderate: 'fips-199-moderate',
    fips_199_high: 'fips-199-high',
  },
};

export default cyioInformationTypeResolvers;
