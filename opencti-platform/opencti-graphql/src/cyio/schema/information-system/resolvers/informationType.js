import {
  findAllInformationTypes,
  findInformationTypeById,
  createInformationType,
  deleteInformationTypeById,
  editInformationTypeById,
  findImpactLevelByIri,
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
      if (parent.categorizations_iris === undefined) return [];

		},
		confidentiality_impact: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.confidentiality_impact_iri === undefined) return null;
      let impact = findImpactLevelByIri(parent.confidentiality_impact_iri, dbName, dataSources, selectMap.getNode('confidentiality_impact'));
      if (impact === undefined || impact === null) return null;
      return impact;
		},
		integrity_impact: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.integrity_impact_iri === undefined) return null;
      let impact = findImpactLevelByIri(parent.integrity_impact_iri, dbName, dataSources, selectMap.getNode('integrity_impact'));
      if (impact === undefined || impact === null) return null;
      return impact;
		},
		availability_impact: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.availability_impact_iri === undefined) return null;
      let impact = findImpactLevelByIri(parent.availability_impact_iri, dbName, dataSources, selectMap.getNode('availability_impact'));
      if (impact === undefined || impact === null) return null;
      return impact;
		}
	},
  // Map enum GraphQL values to data model required values
  FIPS199: {
    fips_199_low: 'fips-199-low',
    fips_199_moderate: 'fips-199-moderate',
    fips_199_high: 'fips-199-high',
  },
};

export default cyioInformationTypeResolvers;
