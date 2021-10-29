import { assetSingularizeSchema as singularizeSchema } from '../asset-mappings.js';
import { getSparqlQuery } from './sparql-query.js';

const assetCommonResolvers = {
  Query: {
    assetList: async ( _, args, context, info  ) => { 
      var sparqlQuery = getSparqlQuery('BY-ALL', args.id);
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
    asset: async ( _, args, context, info ) => {
      var sparqlQuery = getSparqlQuery('BY-ID', args.id);
      const response = await context.dataSources.Stardog.queryById( 
          context.dbName, 
          sparqlQuery, 
          singularizeSchema 
      )
      console.log( response[0] );
      return( itAssetReducer( response[0]) );
    },
    itAssetList: async ( _, args, context, info  ) => { 
      var sparqlQuery = getSparqlQuery('BY-ALL', args.id);
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
    itAsset: async ( _, args, context, info ) => {
      var sparqlQuery = getSparqlQuery('BY-ID', args.id);
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

function itAssetReducer( asset ) {
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
    // Hints
    ...(asset.iri && {parent_iri: asset.iri}),
    ...(asset.locations && {locations_iri: asset.locations}),
    ...(asset.external_references && {ext_ref_iri: asset.external_references}),
    ...(asset.notes && {notes_iri: asset.notes}),
  }
}

export default assetCommonResolvers;