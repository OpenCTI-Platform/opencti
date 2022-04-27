import {riskSingularizeSchema as singularizeSchema} from '../../risk-mappings.js';
import {compareValues, updateQuery, filterValues, toPascalCase, generateId} from '../../../utils.js';
import {UserInputError} from "apollo-server-express";

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
} from './sparql-query.js';

const characterizationResolvers = {
  Query: {
    characterizations: async (_, args, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectAllCharacterizations(selectMap.getNode("node"), args);
      let response;
      try {
        response = await dataSources.Stardog.queryAll({
          dbName,
          sparqlQuery,
          queryId: "Select Characterization List",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const edges = [];
        const reducer = getReducer("CHARACTERIZATION");
        let filterCount, resultCount, limit, offset, limitSize, offsetSize;
        limitSize = limit = (args.first === undefined ? response.length : args.first) ;
        offsetSize = offset = (args.offset === undefined ? 0 : args.offset) ;
        filterCount = 0;
        let characterizationList ;
        if (args.orderedBy !== undefined ) {
          characterizationList = response.sort(compareValues(args.orderedBy, args.orderMode ));
        } else {
          characterizationList = response;
        }

        if (offset > characterizationList.length) return null;

        // for each Risk in the result set
        for (let characterization of characterizationList) {
          // skip down past the offset
          if (offset) {
            offset--
            continue
          }

          if (characterization.id === undefined || characterization.id == null ) {
            console.log(`[CYIO] CONSTRAINT-VIOLATION: (${dbName}) ${characterization.iri} missing field 'id'; skipping`);
            continue;
          }

          // filter out non-matching entries if a filter is to be applied
          if ('filters' in args && args.filters != null && args.filters.length > 0) {
            if (!filterValues(characterization, args.filters, args.filterMode) ) {
              continue
            }
            filterCount++;
          }

          // if haven't reached limit to be returned
          if (limit) {
            let edge = {
              cursor: characterization.iri,
              node: reducer(characterization),
            }
            edges.push(edge)
            limit--;
          }
        }
        // check if there is data to be returned
        if (edges.length === 0 ) return null;
        let hasNextPage = false, hasPreviousPage = false;
        resultCount = characterizationList.length;
        if (edges.length < resultCount) {
          if (edges.length === limitSize && filterCount <= limitSize ) {
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
            endCursor: edges[edges.length-1].cursor,
            hasNextPage: (hasNextPage ),
            hasPreviousPage: (hasPreviousPage),
            globalCount: resultCount,
          },
          edges: edges,
        }
      } else {
        // Handle reporting Stardog Error
        if (typeof (response) === 'object' && 'body' in response) {
          throw new UserInputError(response.statusText, {
            error_details: (response.body.message ? response.body.message : response.body),
            error_code: (response.body.code ? response.body.code : 'N/A')
          });
        } else {
          return null;
        }
      }
    },
    characterization: async (_, {id}, { dbName, dataSources, selectMap }) => {
      const sparqlQuery = selectCharacterizationQuery(id, selectMap.getNode("characterization"));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: "Select Characterization",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const reducer = getReducer("CHARACTERIZATION");
        return reducer(response[0]);  
      } else {
        // Handle reporting Stardog Error
        if (typeof (response) === 'object' && 'body' in response) {
          throw new UserInputError(response.statusText, {
            error_details: (response.body.message ? response.body.message : response.body),
            error_code: (response.body.code ? response.body.code : 'N/A')
          });
        } else {
          return null;
        }
      }
    },
    facets: async (_, args, { dbName, dataSources, selectMap }) => {
      // TODO: Update to support vulnerability-facets
      const sparqlQuery = selectAllFacets(selectMap.getNode("node"), args);
      let response;
      try {
        response = await dataSources.Stardog.queryAll({
          dbName,
          sparqlQuery,
          queryId: "Select Facet List",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const edges = [];
        const reducer = getReducer("FACET");
        let filterCount, resultCount, limit, offset, limitSize, offsetSize;
        limitSize = limit = (args.first === undefined ? response.length : args.first) ;
        offsetSize = offset = (args.offset === undefined ? 0 : args.offset) ;
        filterCount = 0;
        let facetList ;
        if (args.orderedBy !== undefined ) {
          facetList = response.sort(compareValues(args.orderedBy, args.orderMode ));
        } else {
          facetList = response;
        }

        if (offset > facetList.length) return null;

        // for each Risk in the result set
        for (let facet of facetList) {
          // skip down past the offset
          if (offset) {
            offset--
            continue
          }

          if (facet.id === undefined || facet.id == null ) {
            console.log(`[CYIO] CONSTRAINT-VIOLATION: (${dbName}) ${facet.iri} missing field 'id'; skipping`);
            continue;
          }

          // filter out non-matching entries if a filter is to be applied
          if ('filters' in args && args.filters != null && args.filters.length > 0) {
            if (!filterValues(facet, args.filters, args.filterMode) ) {
              continue
            }
            filterCount++;
          }

          // if haven't reached limit to be returned
          if (limit) {
            let edge = {
              cursor: facet.iri,
              node: reducer(facet),
            }
            edges.push(edge)
            limit--;
          }
        }
        // check if there is data to be returned
        if (edges.length === 0 ) return null;
        let hasNextPage = false, hasPreviousPage = false;
        resultCount = facetList.length;
        if (edges.length < resultCount) {
          if (edges.length === limitSize && filterCount <= limitSize ) {
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
            endCursor: edges[edges.length-1].cursor,
            hasNextPage: (hasNextPage ),
            hasPreviousPage: (hasPreviousPage),
            globalCount: resultCount,
          },
          edges: edges,
        }
      } else {
        // Handle reporting Stardog Error
        if (typeof (response) === 'object' && 'body' in response) {
          throw new UserInputError(response.statusText, {
            error_details: (response.body.message ? response.body.message : response.body),
            error_code: (response.body.code ? response.body.code : 'N/A')
          });
        } else {
          return null;
        }
      }
    },
    facet: async (_, {id}, { dbName, dataSources, selectMap }) => {
      // TODO: Update to support vulnerability-facets
      const sparqlQuery = selectFacetQuery(id, selectMap.getNode("facets"));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: "Select Facet",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      if (response === undefined) return null;
      if (Array.isArray(response) && response.length > 0) {
        const reducer = getReducer("FACET");
        return reducer(response[0]);  
      } else {
        // Handle reporting Stardog Error
        if (typeof (response) === 'object' && 'body' in response) {
          throw new UserInputError(response.statusText, {
            error_details: (response.body.message ? response.body.message : response.body),
            error_code: (response.body.code ? response.body.code : 'N/A')
          });
        } else {
          return null;
        }
      }
    },
  },
  Mutation: {
    createCharacterization: async ( _, {input}, {dbName, selectMap, dataSources} ) => {
      // Setup to handle embedded objects to be created
      let facets, origins, riskId;
      if (input.facets !== undefined) facets = input.facets;
      if (input.origins !== undefined) origins = input.origins;
      if (input.risk_id !== undefined) riskId = input.risk_id;

      // create the Characterization
      const {iri, id, query} = insertCharacterizationQuery(input);
      try {
        await dataSources.Stardog.create({
          dbName,
          sparqlQuery: query,
          queryId: "Create Characterization"
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      // add the Characterization to the Risk
      if (riskId !== undefined && riskId !== null) {
        const attachQuery = attachToRiskQuery( riskId, 'characterizations', iri );
        try {
          await dataSources.Stardog.create({
            dbName,
            sparqlQuery: attachQuery,
            queryId: "Add Characterization to Risk"
          });
        } catch (e) {
          console.log(e)
          throw e
        }  
      }

      // create any facets supplied and attach them to the Characterization
      if (facets !== undefined && facets !== null ) {
        // create the facet
        const { facetIris, query } = insertFacetsQuery( facets );
        try {
          await dataSources.Stardog.create({
            dbName,
            sparqlQuery: query,
            queryId: "Create Facets of Characterization"
          });
        } catch (e) {
          console.log(e)
          throw e
        }

        // attach facet to the Characterization
        const facetAttachQuery = attachToCharacterizationQuery(id, 'facets', facetIris );
        try {
          await dataSources.Stardog.create({
            dbName,
            queryId: "Add facet to Characterization",
            sparqlQuery: facetAttachQuery
          });
        } catch (e) {
          console.log(e)
          throw e
        }
      }

      // create any origins supplied and attach them to the Characterization
      if (origins !== undefined && origins !== null ) {
        // create the origin

        // attach origin ot the Characterization
      }

      // retrieve information about the newly created Characterization to return to the user
      const select = selectCharacterizationQuery(id, selectMap.getNode("createCharacterization"));
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery: select,
          queryId: "Select Characterization",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }
      const reducer = getReducer("CHARACTERIZATION");
      return reducer(response[0]);
    },
    deleteCharacterization: async ( _, {riskId, id}, {dbName, dataSources} ) => {
      // check that the characterization exists
      const sparqlQuery = selectCharacterizationQuery(id, null);
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: "Select Characterization",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      if (response.length === 0) throw new UserInputError(`Entity does not exist with ID ${id}`);
      let reducer = getReducer("CHARACTERIZATION");
      const characterization = (reducer(response[0]));

      // Delete any attached facets
      if (characterization.hasOwnProperty('facets_iri')) {
        for (const facetIri of characterization.facets_iri) {
          const facetQuery = deleteFacetByIriQuery(facetIri);
          try {
            await dataSources.Stardog.delete({
              dbName,
              sparqlQuery: facetQuery,
              queryId: "Delete Facet from Characterization"
            });
          } catch (e) {
            console.log(e)
            throw e
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
              queryId: "Delete Origin from Characterization"
            });
          } catch (e) {
            console.log(e)
            throw e
          }    
        }
      }

      // detach the Characterization from the Risk
      if (riskId !== undefined && riskId !== null) {
        const iri = `http://csrc.nist.gov/ns/oscal/assessment/common#Characterization-${id}`
        const detachQuery = detachFromRiskQuery( riskId, 'characterizations', iri );
        try {
          await dataSources.Stardog.delete({
            dbName,
            sparqlQuery: detachQuery,
            queryId: "Detach Characterization from Risk"
          });
        } catch (e) {
          console.log(e)
          throw e
        }
      }
      
      // Delete the characterization itself
      const query = deleteCharacterizationQuery(id);
      try {
        await dataSources.Stardog.delete({
          dbName,
          sparqlQuery: query,
          queryId: "Delete Characterization"
        });
      } catch (e) {
        console.log(e)
        throw e
      }
      return id;
    },
    editCharacterization: async (_, {id, input}, {dbName, dataSources, selectMap}) => {
      // check that the object to be edited exists with the predicates - only get the minimum of data
      let editSelect = ['id'];
      for (let editItem of input) {
        editSelect.push(editItem.key);
      }
      const sparqlQuery = selectCharacterizationQuery(id, editSelect );
      let response = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery,
        queryId: "Select Characterization",
        singularizeSchema
      })
      if (response.length === 0) throw new UserInputError(`Entity does not exist with ID ${id}`);

      // TODO: WORKAROUND to handle UI where it DOES NOT provide an explicit operation
      for (let editItem of input) {
        if (!response[0].hasOwnProperty(editItem.key)) editItem.operation = 'add';
      }
      // END WORKAROUND

      const query = updateQuery(
        `http://csrc.nist.gov/ns/oscal/assessment/common#Characterization-${id}`,
        "http://csrc.nist.gov/ns/oscal/assessment/common#Characterization",
        input,
        characterizationPredicateMap
      )
      await dataSources.Stardog.edit({
        dbName,
        sparqlQuery: query,
        queryId: "Update Characterization"
      });
      const select = selectCharacterizationQuery(id, selectMap.getNode("editCharacterization"));
      const result = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery: select,
        queryId: "Select Characterization",
        singularizeSchema
      });
      const reducer = getReducer("CHARACTERIZATION");
      return reducer(result[0]);
    },
    createFacet: async ( _, {input}, {dbName, selectMap, dataSources}, {schema} ) => {
      // Setup to handle embedded objects to be created
      let characterizationId;
      if (input.characterization_id !== undefined) characterizationId = input.characterization_id;

      // validate the facet against the schema
      if (!validateFacet(input, schema)) {
        throw new UserInputError("Invalid argument value", {
          argumentName: input.facet_name
        });
      }
      // Create the Facet
      const {id, query} = insertFacetQuery(input);
      await dataSources.Stardog.create({
        dbName,
        sparqlQuery: query,
        queryId: "Create Facet"
      });

      // add the Facet to the Characterization
      if (characterizationId !== undefined && characterizationId !== null) {
        const attachQuery = attachToCharacterizationQuery( characterizationId, 'facets', iri );
        try {
          await dataSources.Stardog.create({
            dbName,
            sparqlQuery: attachQuery,
            queryId: "Add Facet to Characterization"
          });
        } catch (e) {
          console.log(e)
          throw e
        }  
      }
      
      const select = selectFacetQuery(id, selectMap.getNode("createFacet"));
      const result = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery: select,
        queryId: "Select Facet",
        singularizeSchema
      });
      const reducer = getReducer("FACET");
      return reducer(result[0]);
    },
    deleteFacet: async ( _, { characterizationId, id}, {dbName, dataSources} ) => {
      // Check that the facet exists
      const sparqlQuery = selectFacetQuery(id, null);
      let response;
      try {
        response = await dataSources.Stardog.queryById({
          dbName,
          sparqlQuery,
          queryId: "Select Facet",
          singularizeSchema
        });
      } catch (e) {
        console.log(e)
        throw e
      }

      if (response.length === 0) throw new UserInputError(`Entity does not exist with ID ${id}`);

      // detach the Facet to the Characterization
      if (characterizationId !== undefined && characterizationId !== null) {
        const iri = `http://csrc.nist.gov/ns/oscal/assessment/common#Facet-${id}`
        const detachQuery = detachFromCharacterizationQuery( characterizationId, 'facets', iri );
        try {
          await dataSources.Stardog.create({
            dbName,
            sparqlQuery: detachQuery,
            queryId: "Remove Facet to Characterization"
          });
        } catch (e) {
          console.log(e)
          throw e
        }  
      }

      // Delete the facet
      const query = deleteFacetQuery(id, null);
      try {
        await dataSources.Stardog.delete({
          dbName,
          sparqlQuery: query,
          queryId: "Delete Facet"
        });
      } catch (e) {
        console.log(e)
        throw e
      }
      return id;
    },
    editFacet: async (_, {id, input}, {dbName, dataSources, selectMap}) => {
      // check that the object to be edited exists with the predicates - only get the minimum of data
      let editSelect = ['id'];
      for (let editItem of input) {
        editSelect.push(editItem.key);
      }
      const sparqlQuery = selectFacetQuery(id, editSelect );
      let response = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery,
        queryId: "Select Facet",
        singularizeSchema
      })
      if (response.length === 0) throw new UserInputError(`Entity does not exist with ID ${id}`);

      // TODO: WORKAROUND to handle UI where it DOES NOT provide an explicit operation
      for (let editItem of input) {
        if (!response[0].hasOwnProperty(editItem.key)) editItem.operation = 'add';
      }
      // END WORKAROUND

      const query = updateQuery(
        `http://csrc.nist.gov/ns/oscal/assessment/common#Facet-${id}`,
        "http://csrc.nist.gov/ns/oscal/assessment/common#Facet",
        input,
        facetPredicateMap
      )
      await dataSources.Stardog.edit({
        dbName,
        sparqlQuery: query,
        queryId: "Update Facet"
      });
      const select = selectFacetQuery(id, selectMap.getNode("editFacet"));
      const result = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery: select,
        queryId: "Select Facet",
        singularizeSchema
      });
      const reducer = getReducer("FACET");
      return reducer(result[0]);
    },
  },
  Characterization: {
    links: async (parent, _, {dbName, dataSources, selectMap}) => {
      if (parent.links_iri === undefined) return [];
      let iriArray = parent.links_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getGlobalReducer("EXTERNAL-REFERENCE");
        for (let iri of iriArray) {
          if (iri === undefined || !iri.includes('ExternalReference')) {
            continue;
          }
          const sparqlQuery = selectExternalReferenceByIriQuery(iri, selectMap.getNode("links"));
          let response;
          try {
            response = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: "Select Link",
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
    remarks: async (parent, _, {dbName, dataSources, selectMap}) => {
      if (parent.remarks_iri === undefined) return [];
      let iriArray = parent.remarks_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getGlobalReducer("NOTE");
        for (let iri of iriArray) {
          if (iri === undefined || !iri.includes('Note')) {
            continue;
          }
          const sparqlQuery = selectNoteByIriQuery(iri, selectMap.getNode("remarks"));
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
    facets: async (parent, _, {dbName, dataSources, }) => {
      if (parent.facets_iri === undefined) return [];
      let iriArray = parent.facets_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        for (let iri of iriArray) {
          if (iri === undefined || !iri.includes('Facet')) continue;

          // get all available predicates since we don't know the kind of facet
          const sparqlQuery = selectFacetByIriQuery(iri, null);
          let response;
          try {
            response = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: "Select Facet",
              singularizeSchema
            });
          } catch (e) {
            console.log(e)
            throw e
          }
          if (response === undefined) return [];
          if (Array.isArray(response) && response.length > 0) {
            const reducer = getReducer( response[0].object_type.toUpperCase() );
            const facet = reducer(response[0]);
            if (facet.entity_type === 'facet') {
              results.push(facet);
              continue;
            }

            // Process DarkLight custom facets

            // Convert the each key/value pair of Vulnerability Facet into an individual OSCAL facet
            for (const [key, value] of Object.entries(facet)) {
              if (key === 'iri' || key === 'id' || key === 'entity_type' || key === 'standard_id' || key === 'risk_state' || key === 'source_system' ) continue;
              if (value === null || value === 'null') continue;
              let id = generateId();
              let newFacet = { 
                id: `${id}`,
                entity_type: 'facet',
                risk_state: `${facet.risk_state}`,
                source_system: `${facet.source_system}`,
                facet_name: `${key}`,
                facet_value: `${value}`,
              }
            results.push(newFacet);
            }
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
    origins: async (parent, _, {dbName, dataSources, selectMap}) => {
      if (parent.origins_iri === undefined) return [];
      let iriArray = parent.origins_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getReducer("ORIGIN");
        for (let iri of iriArray) {
          if (iri === undefined || !iri.includes('Origin')) {
            continue;
          }
          const sparqlQuery = selectOriginByIriQuery(iri, selectMap.getNode("origins"));
          let response;
          try {
            response = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: "Select Origin",
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
}

// function to validate the facet against the schema to determine if custom or defined
// if defined, make sure that the facet value is valid for the specified facet name;
// custom values for valid facet names for a source system is PROHIBITED
function validateFacet( input, schema ) {
  let sourceSystemPrefix, facetNameType, facetValueType;
  if (Object.prototype.hasOwnProperty.call(schema._typeMap, 'FacetSourceSystem')) {
    for (let item of schema._typeMap.FacetSourceSystem._values ) {
      if ( item.name == input.source_system || item.description == input.source_system) {
        sourceSystemPrefix = item.value.split('_')[0];
        break;
      }
    }
    
    // didn't find the FacetSourceSystem enumeration; thus treated as custom  
    if (sourceSystemPrefix === undefined) return true;

    // attempt to find the list of valid facet names for this source system
    facetNameType = `${sourceSystemPrefix}FacetName`;
    if (Object.prototype.hasOwnProperty.call(schema._typeMap, facetNameType)) {
      for ( let nameItem of schema._typeMap[facetNameType]._values ) {
        if ( nameItem.name === input.facet_name ) {
          // CVSS 3.* uses same values for modified versions of the base and temporal metrics
          if (sourceSystemPrefix === 'Cvss3' && nameItem.name.includes('modified_')) {
            facetValueType = sourceSystemPrefix.concat(toPascalCase(nameItem.name.slice(9)));
          } else {
            facetValueType = sourceSystemPrefix.concat(toPascalCase(nameItem.name));
          }

          // attempt to find the list of valid facet values for the facet name in the source system
          if (Object.prototype.hasOwnProperty.call(schema._typeMap, facetValueType)) {
            for (let valueItem of schema._typeMap[facetValueType]._values ) {
              if ( valueItem.name === input.facet_value ) {
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