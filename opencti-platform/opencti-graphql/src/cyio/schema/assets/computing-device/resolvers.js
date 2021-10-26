import { assetSingularizeSchema as singularizeSchema } from '../asset-mappings.js';
import { getSparqlQuery } from './sparql-query.js';

const computingDeviceResolvers = {
  Query: {
    computingDeviceAssetList: async ( _, args, context, info  ) => { 
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
            node: computingDeviceAssetReducer( asset ),
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
    computingDeviceAsset: async ( _, args, context, info ) => {
      const dbName = context.dbName;
      var sparqlQuery = getSparqlQuery('BY-ID', args.id);
      const response = await context.dataSources.Stardog.queryById( dbName, sparqlQuery, singularizeSchema )
        console.log( response[0] );
        return( computingDeviceAssetReducer( response[0]) );
    },
  },
  Mutation: {
    createComputingDeviceAsset: ( parent, args, context, info ) => {
    },
    deleteComputingDeviceAsset: ( parent, args, context, info ) => {
    },
    editComputingDeviceAsset: ( parent, args, context, info ) => {
    },
  },
  // Map enum GraphQL values to data model required values
};

function computingDeviceAssetReducer( asset ) {
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
    cpe_identifier: asset.cpe_identifier || null,
    installation_id: asset.installation_id || null,
    model: asset.model || null,
    motherboard_id: asset.motherboard_id || null,
    baseline_configuration_name: asset.baseline_configuration_name || null,
    function: asset.function || null,
    bios_id: asset.bios_id || null,
    default_gateway: asset.default_gateway || null,
    fqdn: asset.fqdn || null,
    hostname: asset.hostname || null,
    netbios_name: asset.netbios_name || null,
    network_id: asset.network_id || null,
    vlan_id: asset.vlan_id || null,
    uri: asset.uri || null,
    is_publicly_accessible: asset.is_publicly_accessible || null,
    is_scanned: asset.is_scanned || null,
    is_virtual: asset.is_virtual || null,
    // Hints
    parent_iri: asset.iri,
    locations_iri: asset.locations || null,
    ext_ref_iri: asset.external_references || null,
    notes_iri: asset.notes || null,
    installed_hw_iri: asset.installed_hardware || null,
    installed_os_iri: asset.installed_operating_system || null,
    installed_sw_iri: asset.installed_software || null,
    ip_addr_iri: asset.ip_address || null,
    mac_addr_iri: asset.mac_address || null,
    ports_iri: asset.ports || null,
    conn_network_iri: asset.connected_to_network || null,
  }
}

export default computingDeviceResolvers;