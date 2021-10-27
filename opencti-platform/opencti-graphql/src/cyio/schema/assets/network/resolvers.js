import { assetSingularizeSchema as singularizeSchema } from '../asset-mappings.js';
import { getSparqlQuery } from './sparql-query.js';

const networkResolvers = {
  Query: {
    networkAssetList: async ( _, args, context, info ) => {
      var sparqlQuery = getSparqlQuery('BY-ALL', args.id);
      const response = await context.dataSources.Stardog.queryAll( 
        context.dbName, 
        sparqlQuery,
        singularizeSchema,
        args.first,       // limit
        args.offset,      // offset
        args.filter );    // filter
        if (Array.isArray(response) && response.length > 0) {
          // build array of edges
          const edges = [];
          for (let asset of response) {
            let edge = {
              cursor: asset.iri,
              node: networkAssetReducer( asset ),
            }
            edges.push( edge )
          }
          return {
            pageInfo: {
              startCursor: response[0].iri,
              endCursor: response[response.length -1 ].iri,
              hasNextPage: false,
              hasPreviousPage: false,
              globalCount: response.length,
            },
            edges: edges,
          }
        } else {
          return [];
        }
      },
    networkAsset: async (_, args, context, info ) => {
      const dbName = context.dbName;
      var sparqlQuery = getSparqlQuery('BY-ID', args.id);
      const response = await context.dataSources.Stardog.queryById( dbName, sparqlQuery, singularizeSchema )
        console.log( response[0] );
        return( networkAssetReducer( response[0]) );
    }
  },
  Mutation: {
    createNetworkAsset: ( parent, args, context, info ) => {
    },
    deleteNetworkAsset: ( parent, args, context, info ) => {
    },
    editNetworkAsset: ( parent, args, context, info ) => {
    },
  },
  // Map enum GraphQL values to data model required values
  NetworkAsset: {
    network_address_range: (parent, args, context, info ) => {

    }
  }
};
  
function networkAssetReducer( asset ) {
  return {
    id: asset.id,
    name: asset.name || null,
    description: asset.description || null,
    asset_id: asset.asset_id || null,
    asset_type: asset.asset_type || null,
    asset_tag: asset.tag || null,
    serial_number: asset.serial_number || null,
    vendor_name: asset.vendor_name || null,
    version: asset.version || null,
    release_date: asset.release_date || null,
    network_id: asset.network_id || null,
    network_name: asset.network_name || null,
    // Hints
    parent_iri: asset.iri,
    locations_iri: asset.locations || null,
    ext_ref_iri: asset.external_references || null,
    notes_iri: asset.notes || null,
    netaddr_range: asset.network_address_range || null,
  }
}

export default networkResolvers;