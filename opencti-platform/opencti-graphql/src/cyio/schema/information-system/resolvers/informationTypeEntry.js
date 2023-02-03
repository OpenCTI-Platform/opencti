import {
    findAllInformationTypeEntries,
    findInformationTypeEntryById,
    createInformationTypeEntry,
    deleteInformationTypeEntryById,
    editInformationTypeEntryById,
    findImpactDefinitionById,
  } from '../domain/informationTypeEntry.js';
    
  const cyioInformationTypeEntryResolvers = {
    Query: {
      // Information Type Entry
      informationTypeEntries: async (_, args, { dbName, dataSources, selectMap }) => findAllInformationTypeEntries(args, dbName, dataSources, selectMap),
      informationTypeEntry: async (_, { id }, { dbName, dataSources, selectMap }) => findInformationTypeEntryById(id, dbName, dataSources, selectMap),
    },
    Mutation: {
      // Information Type Entry
      createInformationTypeEntry: async (_, { input }, { dbName, selectMap, dataSources }) => createInformationTypeEntry( input, dbName, selectMap, dataSources),
      deleteInformationTypeEntry: async (_, { id }, { dbName, dataSources }) => deleteInformationTypeEntryById( id, dbName, dataSources),
      deleteInformationTypeEntries: async (_, { ids }, { dbName, dataSources }) => deleteInformationTypeEntryById( ids, dbName, dataSources),
      editInformationTypeEntry: async (_, { id, input }, { dbName, dataSources, selectMap }, {schema}) => editInformationTypeEntryById(id, input, dbName, dataSources, selectMap, schema),
    },
    InformationTypeEntry: {
      confidentiality_impact: async (parent, _, { dbName, dataSources, selectMap }) => {
        if (parent.confidentiality_impact_iri === undefined) return [];
        let results = [];
        const reducer = getReducer('IMPACT-DEFINITION');
        for (iri of confidentiality_impact_iri) {
          let result = findImpactDefinitionById(iri, 'confidentiality_impact', dbName, dataSources, selectMap);
          if (result === undefined || result === null) continue;
          results.push(reducer(result));
        }
        return results;
      },
      integrity_impact: async (parent, _, { dbName, dataSources, selectMap }) => {
        if (parent.integrity_impact_iri === undefined) return [];
        let results = [];
        for (iri of integrity_impact_iri) {
          let result = findImpactDefinitionById(iri, 'integrity_impact', dbName, dataSources, selectMap);
          if (result === undefined || result === null) continue;
          results.push(result);
        }
        return results;
      },
      availability_impact: async (parent, _, { dbName, dataSources, selectMap }) => {
        if (parent.availability_impact_iri === undefined) return [];
        let results = [];
        for (iri of confidentiality_impact_iri) {
          let result = findImpactDefinitionById(iri, 'availability_impact', dbName, dataSources, selectMap);
          if (result === undefined || result === null) continue;
          results.push(result);
        }
        return results;
      },
      labels: async (parent, _, { dbName, dataSources, selectMap }) => {
      },
    },
  };
  
  export default cyioInformationTypeEntryResolvers;
  