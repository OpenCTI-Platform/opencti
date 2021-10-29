import { assetSingularizeSchema as singularizeSchema } from '../asset-mappings.js';
import { getSparqlQuery, getReducer } from './sparql-query.js';

const networkResolvers = {
  Query: {
    networkAssetList: async ( _, args, context, info ) => {
      var sparqlQuery = getSparqlQuery('NETWORK', );
      var reducer = getReducer('NETWORK')
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
            node: reducer(asset ),
            // node: networkAssetReducer( asset ),
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
      var sparqlQuery = getSparqlQuery('NETWORK', args.id, );
      var reducer = getReducer('NETWORK')
      const response = await context.dataSources.Stardog.queryById( 
        context.dbName, 
        sparqlQuery, 
        singularizeSchema 
      )
      console.log( response[0] );
      return( reducer( response[0]) );
      // return( networkAssetReducer( response[0]) );
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
    network_address_range: async (parent, args, context,  ) => {
      let item = parent.netaddr_range_iri;
      var sparqlQuery = getSparqlQuery('NETADDR-RANGE', item);
      var reducer = getReducer('NETADDR-RANGE');
      const response = await context.dataSources.Stardog.queryById( 
        context.dbName, 
        sparqlQuery, 
        singularizeSchema 
      )
      if (response && response.length > 0) {
        // console.log( response[0] );
        // let results = ipAddrRangeReducer( response[0] )    TODO: revert when data is passed as objects, instead of string
        let results = reducer( response[0] )
        return {
          id: results.id,
          starting_ip_address: {
            id: "1243",
            ...(results.entity_type && {entity_type: results.entity_type}),
            ip_address_value: results.start_addr_iri
          },
          ending_ip_address: {
            id: "4556",
            ...(results.entity_type && {entity_type: results.entity_type}),
            ip_address_value: results.ending_addr_iri
          }
        }
        return results
      }
    }
  }
};

export default networkResolvers;