import {
  findAllDataSources,
  findDataSourceById,
  createDataSource,
  deleteDataSourceById,
  editDataSourceById,
  findFrequencyTimingByIri,
} from '../domain/dataSource.js';
import {
  findConnectionConfigByIri,
} from '../domain/connectionInformation.js';
import {
  findDataMarkingByIri,
} from '../../data-markings/domain/dataMarkings.js';
import {
  findSourceActivityById,
} from '../domain/workActivity.js';
import {
  getReducer as getGlobalReducer,
  selectExternalReferenceByIriQuery,
  selectNoteByIriQuery,
} from '../../global/resolvers/sparql-query.js';


const cyioDataSourceResolvers = {
  Query: {
    dataSources: async (_, args, { dbName, dataSources, selectMap }) => findAllDataSources(args, dbName, dataSources, selectMap),
    dataSource: async (_, { id }, { dbName, dataSources, selectMap }) => findDataSourceById(id, dbName, dataSources, selectMap),
  },
  Mutation: {
    createDataSource: async (_, { input }, { dbName, selectMap, dataSources }) => createDataSource( input, dbName, selectMap, dataSources),
    deleteDataSource: async (_, { id }, { dbName, dataSources }) => deleteDataSourceById( id, dbName, dataSources),
    deleteDataSources: async (_, { ids }, { dbName, dataSources }) => deleteDataSourceById( ids, dbName, dataSources),
    editDataSource: async (_, { id, input }, { dbName, dataSources, selectMap }, {schema}) => editDataSourceById(id, input, dbName, dataSources, selectMap, schema),
    // Mutation for managing data source
    startDataSource: async (_, { id }, { dbName, dataSources }) => { },
    pauseDataSource: async (_, { id }, { dbName, dataSources }) => { },
    resetDataSource: async (_, { id }, { dbName, dataSources }) => { },
  },
  DataSource: {
    activities: async (parent, { since }, { dbName, dataSources, selectMap }) => {
      return findSourceActivityById(parent.id, since, dataSources);
    },
    update_frequency: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.update_frequency_iri === undefined) return null;
      return findFrequencyTimingByIri(parent.update_frequency_iri, dbName, dataSources, selectMap);
    },
    connection_information: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.connection_information_iri === undefined) return null;
      return findConnectionConfigByIri(parent.connection_information_iri, dbName, dataSources, selectMap);
    },
    iep: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.iep_iri === undefined) return null;
      return findDataMarkingByIri(parent.iep_iri, dbName, dataSources, selectMap);
    },
    external_references: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.external_references_iri === undefined) return [];
      let iriArray = parent.external_references_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getGlobalReducer("EXTERNAL-REFERENCE");
        for (let iri of iriArray) {
          if (iri === undefined || !iri.includes('ExternalReference')) {
            continue;
          }
          const sparqlQuery = selectExternalReferenceByIriQuery(iri, selectMap.getNode("external_references"));
          let response;
          try {
            response = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: "Select External Reference",
              singularizeSchema
            });
          } catch (e) {
            console.log(e)
            throw e
          }
          if (response === undefined) return [];
          if (Array.isArray(response) && response.length > 0) {
            results.push(reducer(response[0]))
          }
          else {
            // Handle reporting Stardog Error
            if (typeof (response) === 'object' && 'body' in response) {
              throw new UserInputError(response.statusText, {
                error_details: (response.body.message ? response.body.message : response.body),
                error_code: (response.body.code ? response.body.code : 'N/A')
              });
            }
          }
        }
        return results;
      } else {
        return [];
      }
    },
    notes: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.notes_iri === undefined) return [];
      let iriArray = parent.notes_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getGlobalReducer("NOTE");
        for (let iri of iriArray) {
          if (iri === undefined || !iri.includes('Note')) {
            continue;
          }
          const sparqlQuery = selectNoteByIriQuery(iri, selectMap.getNode("notes"));
          let response;
          try {
            response = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: "Select Note",
              singularizeSchema
            });
          } catch (e) {
            console.log(e)
            throw e
          }
          if (response === undefined) return [];
          if (Array.isArray(response) && response.length > 0) {
            results.push(reducer(response[0]))
          }
          else {
            // Handle reporting Stardog Error
            if (typeof (response) === 'object' && 'body' in response) {
              throw new UserInputError(response.statusText, {
                error_details: (response.body.message ? response.body.message : response.body),
                error_code: (response.body.code ? response.body.code : 'N/A')
              });
            }
          }
        }
        return results;
      } else {
        return [];
      }
    },
  },
  // Map enum GraphQL values to data model required values
  DataSourceStatus: {
    ACTIVE: 'active',
    INACTIVE: 'inactive',
    NOT_APPLICABLE: 'not-applicable',
  },
  DataSourceType: {
    EXTERNAL_IMPORT: 'external-import',
    EXTERNAL_IMPORT_FILE: 'external-import-file',
    INTERNAL_ENRICHMENT: 'internal-enrichment',
  },
};

export default cyioDataSourceResolvers;
