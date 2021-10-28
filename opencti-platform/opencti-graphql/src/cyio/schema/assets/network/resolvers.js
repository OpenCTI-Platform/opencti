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
    ...(asset.created && {created: asset.created}),
    ...(asset.modified && {modified: asset.modified}),
    ...(asset.labels && {labels: asset.labels}),
    ...(asset.name && { name: asset.name} ),
    ...(asset.description && { description: asset.description}),
    ...(asset.asset_id && { asset_id: asset.asset_id}),
    ...(asset.asset_type && {asset_type: asset.asset_type}),
    ...(asset.asset_tag && {asset_tag: asset.asset_tag}) ,
    ...(asset.serial_number && {serial_number: asset.serial_number}),
    ...(asset.vendor_name && {vendor_name: asset.vendor_name}),
    ...(asset.version && {version: asset.version}),
    ...(asset.release_date && {release_date: asset.release_date}),
    ...(asset.network_id && {network_id: asset.network_id}),
    ...(asset.network_name && {network_name: asset.network_name}),
    // Hints
    ...(asset.iri && {parent_iri: asset.iri}),
    ...(asset.locations && {locations_iri: asset.locations}),
    ...(asset.external_references && {ext_ref_iri: asset.external_references}),
    ...(asset.notes && {notes_iri: asset.notes}),
    ...(asset.network_address_range && {netaddr_range_iri: asset.network_address_range}),
  }
}

export default networkResolvers;