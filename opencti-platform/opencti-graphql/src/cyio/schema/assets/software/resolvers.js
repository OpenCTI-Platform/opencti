import { assetSingularizeSchema as singularizeSchema, objectTypeMapping } from '../asset-mappings.js';
import {compareValues, updateQuery, filterValues} from '../../utils.js';
import {UserInputError} from "apollo-server-express";
import {addToInventoryQuery, deleteQuery, removeFromInventoryQuery} from "../assetUtil.js";
import {
  getSelectSparqlQuery,
  getReducer,
  insertQuery, predicateMap
} from './sparql-query.js';
import {
  selectLabelByIriQuery,
  selectExternalReferenceByIriQuery,
  selectNoteByIriQuery,
  getReducer as getGlobalReducer,
} from '../../global/resolvers/sparql-query.js';

const softwareResolvers = {
  Query: {
    softwareAssetList: async ( _, args, {dbName, dataSources, selectMap})  => {
      const { filter} = args;
      const selectionList = selectMap.getNode("node");
      const sparqlQuery = getSelectSparqlQuery('SOFTWARE', selectionList);
      const reducer = getReducer('SOFTWARE');
      const response = await dataSources.Stardog.queryAll({
              dbName,
              sparqlQuery,
              queryId: "Select Software Assets",
              singularizeSchema
              // args.first,       // limit
              // args.offset,      // offset
              // filter,      // filter
            }
        );

      if (response === undefined) return;
      if (Array.isArray(response) && response.length > 0) {
        // build array of edges
        const edges = [];
        let limit = (args.first === undefined ? response.length : args.first) ;
        let offset = (args.offset === undefined ? 0 : args.offset) ;
        const assetList = (args.orderedBy !== undefined) ? response.sort(compareValues(args.orderedBy, args.orderMode)) : response;

        if (offset > assetList.length) return

        for (const asset of assetList) {
          // skip down past the offset
          if ( offset ) {
            offset--
            continue
          }

          if (asset.id === undefined || asset.id == null ) {
            console.log(`[DATA-ERROR] object ${asset.iri} is missing required properties; skipping object.`);
            continue;
          }

          // filter out non-matching entries if a filter is to be applied
          if ('filters' in args && args.filters != null && args.filters.length > 0) {
            if (!filterValues(asset, args.filters, args.filterMode) ) {
              continue
            }
          }

          // check to make sure not to return more than requested
          if ( limit ) {
            const edge = {
              cursor: asset.iri,
              node: reducer( asset ),
            }
            if (edge.node.name === undefined) {
              console.log(`[WARNING] Required field 'name' missing: ${edge}`)
            }
            edges.push( edge )
            limit-- ;
          }
        }
        if (edges.length == 0) return []
        return {
          pageInfo: {
            startCursor: edges[0].cursor,
            endCursor: edges[edges.length-1].cursor,
            hasNextPage: (args.first < assetList.length ? true : false),
            hasPreviousPage: (args.offset > 0 ? true : false),
            globalCount: assetList.length,
          },
          edges: edges,
        }
      } else {
        // Handle reporting Stardog Error
        if ( typeof(response) === 'object' && 'body' in response) { 
          throw new UserInputError(response.statusText, {
            error_details: (response.body.message ? response.body.message : response.body),
            error_code: (response.body.code ? response.body.code : 'N/A')
          });
        } else {
          return ;
        }
      }
    },
    softwareAsset: async ( _, args, {dbName, dataSources, selectMap} ) => {
      const selectionList = selectMap.getNode("softwareAsset");
      const sparqlQuery = getSelectSparqlQuery('SOFTWARE', selectionList, args.id);
      const reducer = getReducer('SOFTWARE');
      const response = await dataSources.Stardog.queryById({
        dbName,
        sparqlQuery,
        queryId: "Select Software Asset",
        singularizeSchema
      });
      if (response === undefined ) return null;
      if (Array.isArray(response) && response.length > 0) {
        const first = response[0];
        if (first === undefined) return null;
        return( reducer( first ) );
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
    }
  },
  Mutation: {
    createSoftwareAsset: async ( _, {input}, {dbName, dataSources}) => {
      const {iri, id, query} = insertQuery(input);
      await dataSources.Stardog.create({dbName, queryId: "Insert Software Asset",sparqlQuery: query});
      const connectQuery = addToInventoryQuery(iri);
      await dataSources.Stardog.create({dbName, queryId: "Insert to Inventory", sparqlQuery: connectQuery});
      return {...input, id};
    },
    deleteSoftwareAsset: async ( _, {id}, {dbName, dataSources}) => {
      const relationshipQuery = removeFromInventoryQuery(id);
      await dataSources.Stardog.delete({dbName, sparqlQuery:relationshipQuery, queryId: "Remove from Inventory"});
      const query = deleteQuery(id);
      await dataSources.Stardog.delete({dbName, sparqlQuery: query, queryId: "Delete Software Asset"});
      return id;
    },
    editSoftwareAsset: async ( _, {id, input}, {dbName, dataSources}) => {
      const query = updateQuery(
        `http://scap.nist.gov/ns/asset-identification#Software-${id}`,
        "http://scap.nist.gov/ns/asset-identification#Software",
        input,
        predicateMap
      );
      await dataSources.Stardog.edit({dbName, sparqlQuery: query, queryId: "Update Software Asset"});
      return {id};
    },
  },
  SoftwareAsset: {
    labels: async (parent, args, {dbName, dataSources, selectMap}) => {
      let iriArray = parent.labels_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getGlobalReducer("LABEL");
        for (let iri of iriArray) {
          if (iri === undefined || !iri.includes('Label')) continue;
          const sparqlQuery = selectLabelByIriQuery(iri, selectMap.getNode("labels"));
          let response;
          try {
            response = await dataSources.Stardog.queryById({
              dbName,
              sparqlQuery,
              queryId: "Select Label",
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
    external_references: async (parent, args, {dbName, dataSources, selectMap}) => {
      let iriArray = parent.ext_ref_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getGlobalReducer("EXTERNAL-REFERENCE");
        for (let iri of iriArray) {
          if (iri === undefined || !iri.includes('ExternalReference')) continue;
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
    notes: async (parent, args, {dbName, dataSources, selectMap}) => {
      let iriArray = parent.notes_iri;
      const results = [];
      if (Array.isArray(iriArray) && iriArray.length > 0) {
        const reducer = getGlobalReducer("NOTE");
        for (let iri of iriArray) {
          if (iri === undefined || !iri.includes('Note')) continue;
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
  FamilyType: {
    windows: 'windows',
    linux: 'linux',
    macos: 'macos',
    other: 'other',
  },
  SoftwareKind: {
    __resolveType: ( item ) => {
      return objectTypeMapping[item.entity_type];
    }
  }
} ;
  
  
export default softwareResolvers ;
