import { responsePathAsArray } from 'graphql';
import { assetSingularizeSchema as singularizeSchema } from '../asset-mappings.js';
import {
  getSelectSparqlQuery,
  insertQuery,
  addToInventoryQuery,
  deleteQuery,
  removeFromInventoryQuery,
  QueryMode, updateSoftwareQuery
} from './sparql-query.js';
import {ApolloError} from "apollo-errors";

const softwareResolvers = {
  Query: {
    softwareAssetList: async ( _, args, context, info ) => {
      let sparqlQuery = getSelectSparqlQuery(QueryMode.BY_ALL, args.id);
      const response = await context.dataSources.Stardog.queryAll( 
        context.dbName, 
        sparqlQuery,
        singularizeSchema,
        // args.first,       // limit
        // args.offset,      // offset
        args.filter,      // filter
      );
      if (Array.isArray(response) && response.length > 0) {
        // build array of edges
        const edges = [];
        let limit = (args.first === undefined ? response.length : args.first) ;
        let offset = (args.offset === undefined ? 0 : args.offset) ;
        let assetList ;
        if (args.orderedBy !== undefined ) {
          assetList = response.sort(compareValues(args.orderedBy, args.orderMode ));
        } else {
          assetList = response;
        }

        for (let asset of assetList) {
          // skip down past the offset
          if ( offset ) {
            offset--
            continue
          }

          if ( limit ) {
            let edge = {
              cursor: asset.iri,
              node: reducer( asset ),
            }
            if (edge.node.name === undefined) {
              console.log(`[DATA-ERROR]required field 'name' missing ${edge}`)
            }
            edges.push( edge )
            limit-- ;
          }
          edges.push( edge )
        }
        return {
          pageInfo: {
            startCursor: assetList[0].iri,
            endCursor: assetList[assetList.length -1 ].iri,
            hasNextPage: (args.first > assetList.length ? true : false),
            hasPreviousPage: (args.offset > 0 ? true : false),
            globalCount: assetList.length,
          },
          edges: edges,
        }
      } else {
        return ;
      }
    },
    softwareAsset: async ( _, args, context ) => {
      const dbName = context.dbName;
      const sparqlQuery = getSelectSparqlQuery(QueryMode.BY_ID, args.id);
      const response = await context.dataSources.Stardog.queryById( dbName, sparqlQuery, singularizeSchema, )
      if(response === undefined) return null;
      const first = response[0];
      if(first === undefined) return null;
      return( softwareAssetReducer( first) );
    }
  },
  Mutation: {
    createSoftwareAsset: async ( _, {input}, context ) => {
      const dbName = context.dbName;
      const {iri, id, query} = insertQuery(input);
      await context.dataSources.Stardog.create(dbName, query);
      const connectQuery = addToInventoryQuery(iri);
      await context.dataSources.Stardog.create(dbName, connectQuery);
      return {...input, id};
    },
    deleteSoftwareAsset: async ( _, {id}, context ) => {
      const dbName = context.dbName;
      const relationshipQuery = removeFromInventoryQuery(id);
      await context.dataSources.Stardog.delete(dbName, relationshipQuery);
      const query = deleteQuery(id);
      await context.dataSources.Stardog.delete(dbName, query);
      return id;
    },
    editSoftwareAsset: async ( _, {id, input}, context) => {
      const dbName = context.dbName;
      const updateQuery = updateSoftwareQuery(id, input)
      await context.dataSources.Stardog.edit(dbName, updateQuery);
      return {id};
    },
  },
  // Map enum GraphQL values to data model required values
  FamilyType: {
    windows: 'windows',
    linux: 'linux',
    macos: 'macos',
    other: 'other',
  },
} ;
  
function softwareAssetReducer( asset ) {
  return {
    id: asset.id,
    standard_id: asset.standard_id || null,
    entity_type: asset.entity_type || null,
    parent_types: asset.parent_types || null,
    created: asset.created || null,
    modified: asset.modified || null,
    labels: asset.labels || null,
    name: asset.name || null,
    description: asset.description || null,
    asset_id: asset.asset_id || null,
    asset_type: asset.asset_type || null,
    asset_tag: asset.tag || null,
    serial_number: asset.serial_number || null,
    vendor_name: asset.vendor_name || null,
    version: asset.version || null,
    release_date: asset.release_date || null,
    function: asset.function || null,
    cpe_identifier: asset.cpe_identifier || null,
    software_identifier: asset.software_identifier || null,
    patch_level: asset.patch_level || null,
    installation_id: asset.installation_id || null,
    license_key: asset.license_key || null,
    // Hints
    parent_iri: asset.iri,
    locations_iri: asset.locations || null,
    ext_ref_iri: asset.external_references || null,
    notes_iri: asset.notes || null,
  }
}
  
export default softwareResolvers ;
