// import { toSparql } from 'sparqlalgebrajs';
// import { Converter } from 'graphql-to-sparql';
import { Converter as TreeConverter } from 'sparqljson-to-tree';

const assetCommonResolvers = {
  Query: {
    asset: (_, args, context, info) => {
      const dbName = context.dbName;
      var sparqlQuery = getSparqlQuery('BY-ID', args.id);
      context.dataSources.Stardog.queryById( dbName, sparqlQuery, singularizeSchema )
      .then (function (response) {
        console.log( response[0] );
        return( assetReducer( response[0]) );
      }).catch ( function (error) {
        console.log(error);
      });
    },
    assetList: (_, args, context, info) => {
      var sparqlQuery = getSparqlQuery('BY-ALL', args.id);
      const response = context.dataSources.Stardog.filteredQuery( 
        context.dbName, 
        sparqlQuery,
        singularizeSchema,
        args.first,       // limit
        args.offset,      // offset
        args.filter,      // filter
      );
      return Array.isArray( response )
        ? response.map( asset => assetReducer( asset ))
        : [];
    },
    itAsset: ( _, args, context, info) => {
      const dbName = context.dbName;
      var sparqlQuery = getSparqlQuery('BY-ID', args.id);
      context.dataSources.Stardog.queryById( dbName, sparqlQuery, singularizeSchema )
      .then (function (response) {
        console.log( response[0] );
        return( itAssetReducer( response[0]) );
      }).catch ( function (error) {
        console.log(error);
      });
    },
    itAssetList: ( _, args, context, info ) => {
      var sparqlQuery = getSparqlQuery('BY-ALL', args.id);
      const response = context.dataSources.Stardog.filteredQuery( 
        context.dbName, 
        sparqlQuery,
        singularizeSchema,
        args.first,       // limit
        args.offset,      // offset
        args.filter,      // filter
      );
      return Array.isArray( response )
        ? response.map( itAsset => itAssetReducer( itAsset ))
        : [];
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
    }
  },
  AssetLocation: {

  },

};

function assetReducer( asset ) {
  return {
    id: asset.id,
    created: asset.created || null,
    modified: asset.modified || null,
    labels: asset.labels || null,
    name: asset.name || null,
    description: asset.description || null,
    asset_id: asset.asset_id || null,
    //
    //  *** how to get list ***
    //
    // locations
    // external_references
    // notes
  }
}

function itAssetReducer( asset ) {
  return {
    id: asset.id,
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
    //
    //  *** how to get list ***
    //
    // locations
    // external_references
    // notes
  }
}

export default assetCommonResolvers;