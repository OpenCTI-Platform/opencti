import { assetSingularizeSchema as singularizeSchema } from '../asset-mappings.js';
import {
  getSparqlQuery,
  deleteMultipleAssetsQuery,
  removeMultipleAssetsFromInventoryQuery,
  deleteAssetQuery,
  removeAssetFromInventoryQuery,
  itAssetReducer
} from './sparql-query.js';

const assetCommonResolvers = {
  Query: {
    assetList: async ( _, args, context, info  ) => { 
      const sparqlQuery = getSparqlQuery('BY-ALL', args.id);
      const response = await context.dataSources.Stardog.queryAll( 
        context.dbName, 
        sparqlQuery,
        singularizeSchema,
        args.first,       // limit
        args.offset,      // offset
        args.filter       // filter
      )
      if (Array.isArray(response) && response.length > 0) {
        // build array of edges
        const edges = [];
        for (let asset of response) {
          let edge = {
            cursor: asset.iri,
            node: itAssetReducer( asset ),
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
    itAsset: async ( _, args, context ) => {
      const sparqlQuery = getSparqlQuery('BY-ID', args.id);
      const response = await context.dataSources.Stardog.queryById( 
          context.dbName, 
          sparqlQuery, 
          singularizeSchema 
      )
      console.log( response[0] );
      return( itAssetReducer( response[0]) );
    },

  },
  Mutation: {
    deleteAsset: async (_, {id}, context) => {
      const dbName = context.dbName;
      const dq = deleteAssetQuery(id);
      await context.dataSources.Stardog.delete(dbName, dq);
      const ra = removeAssetFromInventoryQuery(id);
      await context.dataSources.Stardog.delete(dbName, ra);
    },
    deleteAssets: async (_, { ids }, context) => {
      const dbName = context.dbName;
      const dq = deleteMultipleAssetsQuery(ids);
      await context.dataSources.Stardog.delete(dbName, dq);
      const ra = removeMultipleAssetsFromInventoryQuery(ids);
      await context.dataSources.Stardog.delete(dbName, ra);
    }
  },
  // Map enum GraphQL values to data model required values
  AssetType: {
    operating_system: 'operating-system',
    database: 'database',
    web_server: 'web-server',
    dns_server: 'dns-server',
    email_server: 'email-server',
    directory_server: 'directory-server',
    pbx: 'pbx',
    firewall: 'firewall',
    router: 'router',
    switch: 'switch',
    storage_array: 'storage-array',
    appliance: 'appliance',
    application_software: 'application-software',
    network_device: 'network-device',
    circuit: 'circuit',
    compute_device: 'compute-device',
    workstation: 'workstation',
    server: 'server',
    network: 'network',
    service: 'service',
    software: 'software',
    physical_device: 'physical-device',
    system: 'system',
    web_site: 'web-site',
    voip_handset: 'voip-handset',
    voip_router: 'voip-router',
  },
  Asset: {
    locations: ( parent, ) => {
    },
    external_references: ( parent, ) => {
    },
    notes: ( parent, ) => {
    },
  },
  AssetLocation: {
  },
  IpAddress: {
    __resolveType: (ipAddress ) => {
      return ipAddress.entity_type
    },
  },
};

export default assetCommonResolvers;