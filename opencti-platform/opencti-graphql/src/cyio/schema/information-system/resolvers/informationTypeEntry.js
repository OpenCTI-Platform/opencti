import {
  findAllInformationTypeEntries,
  findInformationTypeEntryById,
  createInformationTypeEntry,
  deleteInformationTypeEntryById,
  editInformationTypeEntryById,
  findImpactDefinitionById,
  findImpactDefinitionByIri
} from '../domain/informationTypeEntry.js';
import { getReducer } from '../schema/sparql/informationTypeEntry.js';
    
  const cyioInformationTypeEntryResolvers = {
    Query: {
      // Information Type Entry
      informationTypeEntries: async (_, args, { dbName, dataSources, selectMap }) => findAllInformationTypeEntries(args, dbName, dataSources, selectMap.getNode('node')),
      informationTypeEntry: async (_, { id }, { dbName, dataSources, selectMap }) => findInformationTypeEntryById(id, dbName, dataSources, selectMap.getNode('informationTypeEntry')),
    },
    Mutation: {
      // Information Type Entry
      createInformationTypeEntry: async (_, { input }, { dbName, selectMap, dataSources }) => createInformationTypeEntry( input, dbName, selectMap, dataSources),
      deleteInformationTypeEntry: async (_, { id, catalogId }, { dbName, dataSources }) => deleteInformationTypeEntryById( id, catalogId, dbName, dataSources),
      deleteInformationTypeEntries: async (_, { ids, catalogId }, { dbName, dataSources }) => deleteInformationTypeEntryById( ids, catalogId, dbName, dataSources),
      editInformationTypeEntry: async (_, { id, input }, { dbName, dataSources, selectMap }, {schema}) => editInformationTypeEntryById(id, input, dbName, dataSources, selectMap, schema),
    },
    InformationTypeEntry: {
      confidentiality_impact: async (parent, _, { dbName, dataSources, selectMap }) => {
        if (parent.confidentiality_impact_iri === undefined) return null;
        let result = await findImpactDefinitionByIri(parent.confidentiality_impact_iri, 'confidentiality_impact', dbName, dataSources, selectMap.getNode('confidentiality_impact'));
        if (result === undefined || result === null) return null;
        return result;
      },
      integrity_impact: async (parent, _, { dbName, dataSources, selectMap }) => {
        if (parent.integrity_impact_iri === undefined) return null;
        let result = await findImpactDefinitionByIri(parent.integrity_impact_iri, 'integrity_impact', dbName, dataSources, selectMap.getNode('integrity_impact'));
        if (result === undefined || result === null) return null;
        return result;
      },
      availability_impact: async (parent, _, { dbName, dataSources, selectMap }) => {
        if (parent.availability_impact_iri === undefined) return null;
        let result = await findImpactDefinitionByIri(parent.availability_impact_iri, 'availability_impact', dbName, dataSources, selectMap.getNode('availability_impact'));
        if (result === undefined || result === null) return null;
        return result;
      },
      labels: async (parent, _, { dbName, dataSources, selectMap }) => {
      },
    },
  };
  
  export default cyioInformationTypeEntryResolvers;
  