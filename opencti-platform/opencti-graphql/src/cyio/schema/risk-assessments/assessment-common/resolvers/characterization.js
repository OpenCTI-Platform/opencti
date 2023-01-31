import { UserInputError } from 'apollo-server-express';
import { riskSingularizeSchema as singularizeSchema } from '../../risk-mappings.js';
import { compareValues, updateQuery, filterValues, toPascalCase, generateId, CyioError } from '../../../utils.js';

import {
  selectExternalReferenceByIriQuery,
  selectNoteByIriQuery,
  getReducer as getGlobalReducer,
} from '../../../global/resolvers/sparql-query.js';
import {
  getReducer,
  insertCharacterizationQuery,
  selectCharacterizationQuery,
  selectAllCharacterizations,
  deleteCharacterizationQuery,
  insertFacetQuery,
  insertFacetsQuery,
  selectFacetQuery,
  selectFacetByIriQuery,
  selectAllFacets,
  deleteFacetQuery,
  deleteFacetByIriQuery,
  characterizationPredicateMap,
  facetPredicateMap,
  attachToRiskQuery,
  detachFromRiskQuery,
  attachToCharacterizationQuery,
  detachFromCharacterizationQuery,
  selectOriginByIriQuery,
  selectAllOrigins,
} from './sparql-query.js';

const characterizationResolvers = {
  Query: {
    characterizations: async (_, args, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectAllCharacterizations(selectMap.getNode('node'), args);
      let response;
      try {
        response = await dataSources.Stardog.queryAll({
          dbName,
          sparqlQuery,
          queryId: 'Select Characterization List',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const edges = [];
        const reducer = getReducer('CHARACTERIZATION');
        let filterCount;
        let resultCount;
        let limit;
        let offset;
        let limitSize;
        let offsetSize;
        limitSize = limit = args.first === undefined ? response.length : args.first;
        offsetSize = offset = args.offset === undefined ? 0 : args.offset;
        filterCount = 0;
        let characterizationList;
        if (args.orderedBy !== undefined) {
          characterizationList = response.sort(compareValues(args.orderedBy, args.orderMode));
        } else {
          characterizationList = response;
        }

        if (offset > characterizationList.length) return null;

        // for each Risk in the result set
        for (const characterization of characterizationList) {
          // skip down past the offset
          if (offset) {
            offset--;
            continue;
          }

          if (characterization.id === undefined || characterization.id == null) {
            console.log(
              `[CYIO] CONSTRAINT-VIOLATION: (${dbName}) ${characterization.iri} missing field 'id'; skipping`
            );
            continue;
          }

          // filter out non-matching entries if a filter is to be applied
          if ('filters' in args && args.filters != null && args.filters.length > 0) {
            if (!filterValues(characterization, args.filters, args.filterMode)) {
              continue;
            }
            filterCount++;
          }

          // if haven't reached limit to be returned
          if (limit) {
            const edge = {
              cursor: characterization.iri,
              node: reducer(characterization),
            };
            edges.push(edge);
            limit--;
          }
        }
        // check if there is data to be returned
        if (edges.length === 0) return null;
        let hasNextPage = false;
        let hasPreviousPage = false;
        resultCount = characterizationList.length;
        if (edges.length < resultCount) {
          if (edges.length === limitSize && filterCount <= limitSize) {
            hasNextPage = true;
            if (offsetSize > 0) hasPreviousPage = true;
          }
          if (edges.length <= limitSize) {
            if (filterCount !== edges.length) hasNextPage = true;
            if (filterCount > 0 && offsetSize > 0) hasPreviousPage = true;
          }
        }
        return {
          pageInfo: {
            startCursor: edges[0].cursor,
            endCursor: edges[edges.length - 1].cursor,
            hasNextPage,
            hasPreviousPage,
            globalCount: resultCount,
          },
          edges,
        };
      }
      // Handle reporting Stardog Error
      if (typeof response === 'object' && 'body' in response) {
        throw new UserInputError(response.statusText, {
          error_details: response.body.message ? response.body.message : response.body,
          error_code: response.body.code ? response.body.code : 'N/A',
        });
      } else {
        return null;
      }
    },
    characterization: async (_, { id }, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectCharacterizationQuery(id, selectMap.getNode('characterization'));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: 'Select Characterization',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const reducer = getReducer('CHARACTERIZATION');
        return reducer(response[0]);
      }
      // Handle reporting Stardog Error
      if (typeof response === 'object' && 'body' in response) {
        throw new UserInputError(response.statusText, {
          error_details: response.body.message ? response.body.message : response.body,
          error_code: response.body.code ? response.body.code : 'N/A',
        });
      } else {
        return null;
      }
    },
    facets: async (_, args, { dbName, dataSources, selectMap }) => {
      // TODO: Update to support vulnerability-facets
      const sparqlQuery = selectAllFacets(selectMap.getNode('node'), args);
      let response;
      try {
        response = await dataSources.Stardog.queryAll({
          dbName,
          sparqlQuery,
          queryId: 'Select Facet List',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const edges = [];
        const reducer = getReducer('FACET');
        let filterCount;
        let resultCount;
        let limit;
        let offset;
        let limitSize;
        let offsetSize;
        limitSize = limit = args.first === undefined ? response.length : args.first;
        offsetSize = offset = args.offset === undefined ? 0 : args.offset;
        filterCount = 0;
        let facetList;
        if (args.orderedBy !== undefined) {
          facetList = response.sort(compareValues(args.orderedBy, args.orderMode));
        } else {
          facetList = response;
        }

        if (offset > facetList.length) return null;

        // for each Risk in the result set
        for (const facet of facetList) {
          // skip down past the offset
          if (offset) {
            offset--;
            continue;
          }

          if (facet.id === undefined || facet.id == null) {
            console.log(`[CYIO] CONSTRAINT-VIOLATION: (${dbName}) ${facet.iri} missing field 'id'; skipping`);
            continue;
          }

          // filter out non-matching entries if a filter is to be applied
          if ('filters' in args && args.filters != null && args.filters.length > 0) {
            if (!filterValues(facet, args.filters, args.filterMode)) {
              continue;
            }
            filterCount++;
          }

          // if haven't reached limit to be returned
          if (limit) {
            const edge = {
              cursor: facet.iri,
              node: reducer(facet),
            };
            edges.push(edge);
            limit--;
          }
        }
        // check if there is data to be returned
        if (edges.length === 0) return null;
        let hasNextPage = false;
        let hasPreviousPage = false;
        resultCount = facetList.length;
        if (edges.length < resultCount) {
          if (edges.length === limitSize && filterCount <= limitSize) {
            hasNextPage = true;
            if (offsetSize > 0) hasPreviousPage = true;
          }
          if (edges.length <= limitSize) {
            if (filterCount !== edges.length) hasNextPage = true;
            if (filterCount > 0 && offsetSize > 0) hasPreviousPage = true;
          }
        }
        return {
          pageInfo: {
            startCursor: edges[0].cursor,
            endCursor: edges[edges.length - 1].cursor,
            hasNextPage,
            hasPreviousPage,
            globalCount: resultCount,
          },
          edges,
        };
      }
      // Handle reporting Stardog Error
      if (typeof response === 'object' && 'body' in response) {
        throw new UserInputError(response.statusText, {
          error_details: response.body.message ? response.body.message : response.body,
          error_code: response.body.code ? response.body.code : 'N/A',
        });
      } else {
        return null;
      }
    },
    facet: async (_, { id }, { dbName, dataSources, selectMap }) => {
      // TODO: Update to support vulnerability-facets
      const sparqlQuery = selectFacetQuery(id, selectMap.getNode('facets'));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: 'Select Facet',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const reducer = getReducer('FACET');
        return reducer(response[0]);
      }
      // Handle reporting Stardog Error
      if (typeof response === 'object' && 'body' in response) {
        throw new UserInputError(response.statusText, {
          error_details: response.body.message ? response.body.message : response.body,
          error_code: response.body.code ? response.body.code : 'N/A',
        });
      } else {
        return null;
      }
    },
  },
  Mutation: {
    createCharacterization: async (_, { input }, { dbName, selectMap, dataSources }) => {
      // Setup to handle embedded objects to be created
      let facets;
      let origins;
      let riskId;
      if (input.facets !== undefined) facets = input.facets;
      if (input.origins !== undefined) origins = input.origins;
      if (input.risk_id !== undefined) riskId = input.risk_id;

      // create the Characterization
      const { iri, id, query } = insertCharacterizationQuery(input);
      try {
        await dataSources.Stardog.create({
          dbName,
          sparqlQuery: query,
          queryId: 'Create Characterization',
        });
      } catch (e) {
        console.log(e);
        throw e;
      }

      // add the Characterization to the Risk
      if (riskId !== undefined && riskId !== null) {
        const attachQuery = attachToRiskQuery(riskId, 'characterizations', iri);
        try {
          await dataSources.Stardog.create({
            dbName,
            sparqlQuery: attachQuery,
            queryId: 'Add Characterization to Risk',
          });
        } catch (e) {
          console.log(e);
          throw e;
        }
      }

      // create any facets supplied and attach them to the Characterization
      if (facets !== undefined && facets !== null) {
        // create the facet
        const { facetIris, query } = insertFacetsQuery(facets);
        try {
          await dataSources.Stardog.create({
            dbName,
            sparqlQuery: query,
            queryId: 'Create Facets of Characterization',
          });
        } catch (e) {
          console.log(e);
          throw e;
        }

        // attach facet to the Characterization
        const facetAttachQuery = attachToCharacterizationQuery(id, 'facets', facetIris);
        try {
          await dataSources.Stardog.create({
            dbName,
            queryId: 'Add facet to Characterization',
            sparqlQuery: facetAttachQuery,
          });
        } catch (e) {
          console.log(e);
          throw e;
        }
      }

      // create any origins supplied and attach them to the Characterization
      if (origins !== undefined && origins !== null) {
        // create the origin
        // attach origin ot the Characterization
      }

      // retrieve information about the newly created Characterization to return to the user
      const select = selectCharacterizationQuery(id, selectMap.getNode('createCharacterization'));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery: select,
          queryId: 'Select Characterization',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }
      const reducer = getReducer('CHARACTERIZATION');
      return reducer(response[0]);
    },
    deleteCharacterization: async (_, { riskId, id }, { dbName, dataSources }) => {
      // check that the characterization exists
      const sparqlQuery = selectCharacterizationQuery(id, null);
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: 'Select Characterization',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }

      if (response.length === 0) throw new CyioError(`Entity does not exist with ID ${id}`);
      const reducer = getReducer('CHARACTERIZATION');
      const characterization = reducer(response[0]);

      // Delete any attached facets
      if (characterization.hasOwnProperty('facets_iri')) {
        for (const facetIri of characterization.facets_iri) {
          const facetQuery = deleteFacetByIriQuery(facetIri);
          try {
            await dataSources.Stardog.delete({
              dbName,
              sparqlQuery: facetQuery,
              queryId: 'Delete Facet from Characterization',
            });
          } catch (e) {
            console.log(e);
            throw e;
          }
        }
      }

      // Delete any attached origins
      if (characterization.hasOwnProperty('origins_iri')) {
        for (const originIri of characterization.origins_iri) {
          const originQuery = deleteOriginByIriQuery(originIri);
          try {
            await dataSources.Stardog.delete({
              dbName,
              sparqlQuery: originQuery,
              queryId: 'Delete Origin from Characterization',
            });
          } catch (e) {
            console.log(e);
            throw e;
          }
        }
      }

      // detach the Characterization from the Risk
      if (riskId !== undefined && riskId !== null) {
        const iri = `http://csrc.nist.gov/ns/oscal/assessment/common#Characterization-${id}`;
        const detachQuery = detachFromRiskQuery(riskId, 'characterizations', iri);
        try {
          await dataSources.Stardog.delete({
            dbName,
            sparqlQuery: detachQuery,
            queryId: 'Detach Characterization from Risk',
          });
        } catch (e) {
          console.log(e);
          throw e;
        }
      }

      // Delete the characterization itself
      const query = deleteCharacterizationQuery(id);
      try {
        await dataSources.Stardog.delete({
          dbName,
          sparqlQuery: query,
          queryId: 'Delete Characterization',
        });
      } catch (e) {
        console.log(e);
        throw e;
      }
      return id;
    },
    editCharacterization: async (_, { id, input }, { dbName, dataSources, selectMap }) => {
      // make sure there is input data containing what is to be edited
      if (input === undefined || input.length === 0) throw new CyioError(`No input data was supplied`);

      // TODO: WORKAROUND to remove immutable fields
      input = input.filter(
        (element) => element.key !== 'id' && element.key !== 'created' && element.key !== 'modified'
      );

      // check that the object to be edited exists with the predicates - only get the minimum of data
      const editSelect = ['id'];
      for (const editItem of input) {
        editSelect.push(editItem.key);
      }

      const sparqlQuery = selectCharacterizationQuery(id, editSelect);
      const response = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery,
        queryId: 'Select Characterization',
        singularizeSchema,
      });
      if (response.length === 0) throw new CyioError(`Entity does not exist with ID ${id}`);

      // determine operation, if missing
      for (const editItem of input) {
        if (editItem.operation !== undefined) continue;

        // if value if empty then treat as a remove
        if (editItem.value.length === 0 || editItem.value[0].length === 0) {
          editItem.operation = 'remove';
          continue;
        }
        if (!response[0].hasOwnProperty(editItem.key)) {
          editItem.operation = 'add';
        } else {
          editItem.operation = 'replace';
        }
      }

      const query = updateQuery(
        `http://csrc.nist.gov/ns/oscal/assessment/common#Characterization-${id}`,
        'http://csrc.nist.gov/ns/oscal/assessment/common#Characterization',
        input,
        characterizationPredicateMap
      );
      if (query !== null) {
        let response;
        try {
          response = await dataSources.Stardog.edit({
            dbName,
            sparqlQuery: query,
            queryId: 'Update OSCAL Characterization',
          });
        } catch (e) {
          console.log(e);
          throw e;
        }

        if (response !== undefined && 'status' in response) {
          if (response.ok === false || response.status > 299) {
            // Handle reporting Stardog Error
            throw new UserInputError(response.statusText, {
              error_details: response.body.message ? response.body.message : response.body,
              error_code: response.body.code ? response.body.code : 'N/A',
            });
          }
        }
      }

      const select = selectCharacterizationQuery(id, selectMap.getNode('editCharacterization'));
      const result = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery: select,
        queryId: 'Select Characterization',
        singularizeSchema,
      });
      const reducer = getReducer('CHARACTERIZATION');
      return reducer(result[0]);
    },
    createFacet: async (_, { input }, { dbName, selectMap, dataSources }, { schema }) => {
      // Setup to handle embedded objects to be created
      let characterizationId;
      if (input.characterization_id !== undefined) characterizationId = input.characterization_id;

      // validate the facet against the schema
      if (!validateFacet(input, schema)) {
        throw new CyioError('Invalid argument value', {
          argumentName: input.facet_name,
        });
      }
      // Create the Facet
      const { id, query } = insertFacetQuery(input);
      await dataSources.Stardog.create({
        dbName,
        sparqlQuery: query,
        queryId: 'Create Facet',
      });

      // add the Facet to the Characterization
      if (characterizationId !== undefined && characterizationId !== null) {
        const attachQuery = attachToCharacterizationQuery(characterizationId, 'facets', iri);
        try {
          await dataSources.Stardog.create({
            dbName,
            sparqlQuery: attachQuery,
            queryId: 'Add Facet to Characterization',
          });
        } catch (e) {
          console.log(e);
          throw e;
        }
      }

      const select = selectFacetQuery(id, selectMap.getNode('createFacet'));
      const result = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery: select,
        queryId: 'Select Facet',
        singularizeSchema,
      });
      const reducer = getReducer('FACET');
      return reducer(result[0]);
    },
    deleteFacet: async (_, { characterizationId, id }, { dbName, dataSources }) => {
      // Check that the facet exists
      const sparqlQuery = selectFacetQuery(id, null);
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: 'Select Facet',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }

      if (response.length === 0) throw new CyioError(`Entity does not exist with ID ${id}`);

      // detach the Facet to the Characterization
      if (characterizationId !== undefined && characterizationId !== null) {
        const iri = `http://csrc.nist.gov/ns/oscal/assessment/common#Facet-${id}`;
        const detachQuery = detachFromCharacterizationQuery(characterizationId, 'facets', iri);
        try {
          await dataSources.Stardog.create({
            dbName,
            sparqlQuery: detachQuery,
            queryId: 'Remove Facet to Characterization',
          });
        } catch (e) {
          console.log(e);
          throw e;
        }
      }

      // Delete the facet
      const query = deleteFacetQuery(id, null);
      try {
        await dataSources.Stardog.delete({
          dbName,
          sparqlQuery: query,
          queryId: 'Delete Facet',
        });
      } catch (e) {
        console.log(e);
        throw e;
      }
      return id;
    },
    editFacet: async (_, { id, input }, { dbName, dataSources, selectMap }) => {
      // make sure there is input data containing what is to be edited
      if (input === undefined || input.length === 0) throw new CyioError(`No input data was supplied`);

      // TODO: WORKAROUND to remove immutable fields
      input = input.filter(
        (element) => element.key !== 'id' && element.key !== 'created' && element.key !== 'modified'
      );

      // check that the object to be edited exists with the predicates - only get the minimum of data
      const editSelect = ['id', 'created', 'modified'];
      for (const editItem of input) {
        editSelect.push(editItem.key);
      }

      const sparqlQuery = selectFacetQuery(id, editSelect);
      const response = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery,
        queryId: 'Select Facet',
        singularizeSchema,
      });
      if (response.length === 0) throw new CyioError(`Entity does not exist with ID ${id}`);

      // determine operation, if missing
      for (const editItem of input) {
        if (editItem.operation !== undefined) continue;

        // if value if empty then treat as a remove
        if (editItem.value.length === 0 || editItem.value[0].length === 0) {
          editItem.operation = 'remove';
          continue;
        }
        if (!response[0].hasOwnProperty(editItem.key)) {
          editItem.operation = 'add';
        } else {
          editItem.operation = 'replace';
        }
      }

      const query = updateQuery(
        `http://csrc.nist.gov/ns/oscal/assessment/common#Facet-${id}`,
        'http://csrc.nist.gov/ns/oscal/assessment/common#Facet',
        input,
        facetPredicateMap
      );
      if (query !== null) {
        let response;
        try {
          response = await dataSources.Stardog.edit({
            dbName,
            sparqlQuery: query,
            queryId: 'Update OSCAL Facet',
          });
        } catch (e) {
          console.log(e);
          throw e;
        }

        if (response !== undefined && 'status' in response) {
          if (response.ok === false || response.status > 299) {
            // Handle reporting Stardog Error
            throw new UserInputError(response.statusText, {
              error_details: response.body.message ? response.body.message : response.body,
              error_code: response.body.code ? response.body.code : 'N/A',
            });
          }
        }
      }

      const select = selectFacetQuery(id, selectMap.getNode('editFacet'));
      const result = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery: select,
        queryId: 'Select Facet',
        singularizeSchema,
      });
      const reducer = getReducer('FACET');
      return reducer(result[0]);
    },
  },
  Characterization: {
    links: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.links_iri === undefined) return [];
      const iriArray = parent.links_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getGlobalReducer('EXTERNAL-REFERENCE');
        for (const iri of iriArray) {
          if (iri === undefined || !iri.includes('ExternalReference')) {
            continue;
          }
          const sparqlQuery = selectExternalReferenceByIriQuery(iri, selectMap.getNode('links'));
          let response;
          try {
            response = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: 'Select Link',
              singularizeSchema,
            });
          } catch (e) {
            console.log(e);
            throw e;
          }
          if (response === undefined) return [];
          if (Array.isArray(response) && response.length > 0) {
            results.push(reducer(response[0]));
          } else {
            // Handle reporting Stardog Error
            if (typeof response === 'object' && 'body' in response) {
              throw new UserInputError(response.statusText, {
                error_details: response.body.message ? response.body.message : response.body,
                error_code: response.body.code ? response.body.code : 'N/A',
              });
            }
          }
        }
        return results;
      }
      return [];
    },
    remarks: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.remarks_iri === undefined) return [];
      const iriArray = parent.remarks_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getGlobalReducer('NOTE');
        for (const iri of iriArray) {
          if (iri === undefined || !iri.includes('Note')) {
            continue;
          }
          const sparqlQuery = selectNoteByIriQuery(iri, selectMap.getNode('remarks'));
          let response;
          try {
            response = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: 'Select Note',
              singularizeSchema,
            });
          } catch (e) {
            console.log(e);
            throw e;
          }
          if (response === undefined) return [];
          if (Array.isArray(response) && response.length > 0) {
            results.push(reducer(response[0]));
          } else {
            // Handle reporting Stardog Error
            if (typeof response === 'object' && 'body' in response) {
              throw new UserInputError(response.statusText, {
                error_details: response.body.message ? response.body.message : response.body,
                error_code: response.body.code ? response.body.code : 'N/A',
              });
            }
          }
        }
        return results;
      }
      return [];
    },
    facets: async (parent, _, { dbName, dataSources }) => {
      if (parent.facets_iri === undefined) return [];
      const iriArray = parent.facets_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        for (const iri of iriArray) {
          if (iri === undefined || !iri.includes('Facet')) continue;

          // get all available predicates since we don't know the kind of facet
          const sparqlQuery = selectFacetByIriQuery(iri, null);
          let response;
          try {
            response = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: 'Select Facet',
              singularizeSchema,
            });
          } catch (e) {
            console.log(e);
            throw e;
          }
          if (response === undefined) return [];
          if (Array.isArray(response) && response.length > 0) {
            const reducer = getReducer(response[0].object_type.toUpperCase());
            const facet = reducer(response[0]);
            if (facet.entity_type === 'facet') {
              results.push(facet);
              continue;
            }

            // Process DarkLight custom facets

            // Convert the each key/value pair of Vulnerability Facet into an individual OSCAL facet
            for (let [key, value] of Object.entries(facet)) {
              if (
                key === 'iri' ||
                key === 'id' ||
                key === 'entity_type' ||
                key === 'standard_id' ||
                key === 'risk_state' ||
                key === 'source_system'
              )
                continue;
              if (value === null || value === 'null') continue;
              if (key.includes('_')) key = key.replace(/_/g, '-');
              switch (key) {
                case 'vulnerability-id':
                  if (value.startsWith('CVE')) {
                    key = 'cve-id';
                    facet.source_system = 'http://cve.mitre.org';
                  } else {
                    facet.source_system = 'http://darklight.ai/ns/oscal';
                  }
                  break;
                case 'cvss20-base-score':
                  key = 'cvss2-base-score';
                  facet.source_system = 'http://www.first.org/cvss/v2.0';
                  break;
                case 'cvss20-temporal-score':
                  key = 'cvss2-temporal-score';
                  facet.source_system = 'http://www.first.org/cvss/v2.0';
                  break;
                case 'cvss20-vector-string':
                  key = 'cvss2-vector';
                  facet.source_system = 'http://www.first.org/cvss/v2.0';
                  break;
                case 'cvss30-base-score':
                  key = 'cvss3-base-score';
                  facet.source_system = 'http://www.first.org/cvss/v3.0';
                  break;
                case 'cvss30-temporal-score':
                  key = 'cvss2-base-score';
                  facet.source_system = 'http://www.first.org/cvss/v3.0';
                  break;
                case 'cvss30-vector-string':
                  key = 'cvss3-vector';
                  facet.source_system = 'http://www.first.org/cvss/v3.0';
                  break;
              }
              const id = generateId();
              const newFacet = {
                id: `${id}`,
                entity_type: 'facet',
                risk_state: `${facet.risk_state}`,
                source_system: `${facet.source_system}`,
                facet_name: `${key}`,
                facet_value: `${value}`,
              };
              results.push(newFacet);
            }
          } else {
            // Handle reporting Stardog Error
            if (typeof response === 'object' && 'body' in response) {
              throw new UserInputError(response.statusText, {
                error_details: response.body.message ? response.body.message : response.body,
                error_code: response.body.code ? response.body.code : 'N/A',
              });
            }
          }
        }
        return results;
      }
      return [];
    },
    origins: async (parent, _, { dbName, dataSources, selectMap }) => {
      if (parent.origins_iri === undefined) return [];
      const results = [];
      const reducer = getReducer('ORIGIN');
      const sparqlQuery = selectAllOrigins(selectMap.getNode('origins'), undefined, parent);
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: 'Select Referenced Origins',
          singularizeSchema,
        });
      } catch (e) {
        console.log(e);
        throw e;
      }
      if (response === undefined || response.length === 0) return null;

      // Handle reporting Stardog Error
      if (typeof response === 'object' && 'body' in response) {
        throw new UserInputError(response.statusText, {
          error_details: response.body.message ? response.body.message : response.body,
          error_code: response.body.code ? response.body.code : 'N/A',
        });
      }

      for (const origin of response) {
        results.push(reducer(origin));
      }

      // check if there is data to be returned
      if (results.length === 0) return [];
      return results;
    },
  },
};

// function to validate the facet against the schema to determine if custom or defined
// if defined, make sure that the facet value is valid for the specified facet name;
// custom values for valid facet names for a source system is PROHIBITED
function validateFacet(input, schema) {
  let sourceSystemPrefix;
  let facetNameType;
  let facetValueType;
  if (Object.prototype.hasOwnProperty.call(schema._typeMap, 'FacetSourceSystem')) {
    for (const item of schema._typeMap.FacetSourceSystem._values) {
      if (item.name == input.source_system || item.description == input.source_system) {
        sourceSystemPrefix = item.value.split('_')[0];
        break;
      }
    }

    // didn't find the FacetSourceSystem enumeration; thus treated as custom
    if (sourceSystemPrefix === undefined) return true;

    // attempt to find the list of valid facet names for this source system
    facetNameType = `${sourceSystemPrefix}FacetName`;
    if (Object.prototype.hasOwnProperty.call(schema._typeMap, facetNameType)) {
      for (const nameItem of schema._typeMap[facetNameType]._values) {
        if (nameItem.name === input.facet_name) {
          // CVSS 3.* uses same values for modified versions of the base and temporal metrics
          if (sourceSystemPrefix === 'Cvss3' && nameItem.name.includes('modified_')) {
            facetValueType = sourceSystemPrefix.concat(toPascalCase(nameItem.name.slice(9)));
          } else {
            facetValueType = sourceSystemPrefix.concat(toPascalCase(nameItem.name));
          }

          // attempt to find the list of valid facet values for the facet name in the source system
          if (Object.prototype.hasOwnProperty.call(schema._typeMap, facetValueType)) {
            for (const valueItem of schema._typeMap[facetValueType]._values) {
              if (valueItem.name === input.facet_value) {
                // facet value was valid for the specified facet name in the specified source system
                return true;
              }
            }
            // facet value was not valid for specified facet name in the specified source system
            return false;
          }
          // no specific facet value type enumeration exists; thus custom
          return true;
        }
      }
      // facet name was unknown for the specified source system; thus treated as custom
      return true;
    }
  }
  // didn't find the FacetSourceSystem enumeration; thus treated as custom
  return true;
}

export default characterizationResolvers;
