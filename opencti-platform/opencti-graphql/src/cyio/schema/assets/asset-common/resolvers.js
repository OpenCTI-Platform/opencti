import { assetSingularizeSchema as singularizeSchema, objectTypeMapping } from '../asset-mappings.js';
import { getSelectSparqlQuery, getReducer } from './sparql-query.js';
import { compareValues } from '../../utils.js';

const assetCommonResolvers = {
  Query: {
    assetList: async ( _, args, context, info  ) => { 
      var sparqlQuery = getSelectSparqlQuery('ASSET', );
      var reducer = getReducer('ASSET');
      const response = await context.dataSources.Stardog.queryAll( 
        context.dbName, 
        sparqlQuery,
        singularizeSchema,
        // args.first,       // limit
        // args.offset,      // offset
        args.filter       // filter
      )
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

        // for each asset in the result set
        for (let asset of assetList) {
          // skip down past the offset
          if ( offset ) {
            offset--
            continue
          }

          // if haven't reached limit to be returned
          if ( limit ) {
            let edge = {
              cursor: asset.iri,
              node: reducer( asset ),
            }
            edges.push( edge )
            limit-- ;
          }
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
        return;
      }
    },
    asset: async ( _, args, context, info ) => {
      var sparqlQuery = getSelectSparqlQuery('ASSET', args.id);
      var reducer = getReducer('ASSET');
      const response = await context.dataSources.Stardog.queryById( context.dbName, sparqlQuery, singularizeSchema )
      if (response === undefined ) return null;
      const first = response[0];
      if (first === undefined) return null;
      return( reducer( first ) );
    },
    itAssetList: async ( _, args, context, info  ) => { 
      var sparqlQuery = getSelectSparqlQuery('IT-ASSET', );
      var reducer = getReducer('IT-ASSET');
      const response = await context.dataSources.Stardog.queryAll( 
        context.dbName, 
        sparqlQuery,
        singularizeSchema,
        // args.first,       // limit
        // args.offset,      // offset
        args.filter       // filter
      )
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

        // for each asset in the result set
        for (let asset of assetList) {
          // skip down past the offset
          if ( offset ) {
            offset--
            continue
          }

          // if haven't reached limit to be returned
          if ( limit ) {
            let edge = {
              cursor: asset.iri,
              node: reducer( asset ),
            }
            edges.push( edge )
            limit-- ;
          }
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
        return;
      }
    },
    itAsset: async ( _, args, context, info ) => {
      var sparqlQuery = getSelectSparqlQuery('IT-ASSET', args.id);
      var reducer = getReducer('IT-ASSET');
      const response = await context.dataSources.Stardog.queryById( context.dbName, sparqlQuery, singularizeSchema )
      if (response === undefined ) return null;
      const first = response[0];
      if (first === undefined) return null;
      return( reducer( first ) );
    },

  },
  Mutation: {

  },
  // Map enum GraphQL values to data model required values
  AssetType: {
    account: 'account',
    appliance: 'appliance',
    application_software: 'application-software',
    circuit: 'circuit',
    computer_account: 'computer-account',
    compute_device: 'compute-device',
    data: 'data',
    database: 'database',
    directory_server: 'directory-server',
    dns_server: 'dns-server',
    email_server: 'email-server',
    embedded: 'embedded',
    firewall: 'firewall',
    guidance: 'guidance',
    hypervisor: 'hypervisor',
    load_balancer: 'load-balancer',
    network_device: 'network-device',
    network: 'network',
    operating_system: 'operating-system',
    pbx: 'pbx',
    physical_device: 'physical-device',
    plan: 'plan',
    policy: 'policy',
    printer: 'printer',
    procedure: 'procedure',
    router: 'router',
    server: 'server',
    service_account: 'service-account',
    service: 'service',
    software: 'software',
    standard: 'standard',
    storage_array: 'storage-array',
    switch: 'switch',
    system: 'system',
    user_account: 'user-account',
    validation: 'validation',
    voip_device: 'voip-device',
    voip_handset: 'voip-handset',
    voip_router: 'voip-router',
    web_server: 'web-server',
    web_site: 'web-site',
    workstation: 'workstation',
  },
  Asset: {
    __resolveType: ( item ) => {
      return objectTypeMapping[item.entity_type];
    },
    locations: ( parent, ) => {
    },
    external_references: ( parent, ) => {
    },
    notes: ( parent, ) => {
    },
  },
  AssetLocation: {
  },
  HardwareAsset: {
    __resolveType: ( item ) => {
      return objectTypeMapping[item.entity_type];
    }
  },
  ItAsset: {
    __resolveType: ( item ) => {
      return objectTypeMapping[item.entity_type];
    }
  },
  AssetKind: {
    __resolveType: ( item ) => {
      return objectTypeMapping[item.entity_type];
    }
  },
  HardwareKind: {
    __resolveType: ( item ) => {
      return objectTypeMapping[item.entity_type];
    }
  },
  ItAssetKind: {
    __resolveType: ( item ) => {
      return objectTypeMapping[item.entity_type];
    }
  },
  IpAddress: {
    __resolveType: ( item ) => {
      return objectTypeMapping[item.entity_type];
    },
  },
  PortRange: {
    __resolveType: ( item ) => {
      return objectTypeMapping[item.entity_type];
    }
  },
};

export default assetCommonResolvers;