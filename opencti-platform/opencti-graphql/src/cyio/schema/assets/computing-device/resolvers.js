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
    ...(asset.function && {function: asset.function}),
    ...(asset.cpe_identifier && {cpe_identifier: asset.cpe_identifier}),
    ...(asset.installation_id && {installation_id: asset.installation_id}),
    ...(asset.model && {model: asset.model}),
    ...(asset.motherboard_id && {motherboard_id: asset.motherboard_id}),
    ...(asset.bios_id && {bios_id: asset.bios_id}),
    ...(asset.network_id && {network_id: asset.network_id}),
    ...(asset.vlan_id && {vlan_id: asset.vlan_id}),
    ...(asset.default_gateway && {default_gateway: asset.default_gateway}),
    ...(asset.fqdn && {fqdn: asset.fqdn}),
    ...(asset.hostname && {hostname: asset.hostname}),
    ...(asset.netbios_name && {netbios_name: asset.netbios_name}),
    ...(asset.uri && {uri: asset.uri}),
    ...(asset.baseline_configuration_name && {baseline_configuration_name: asset.baseline_configuration_name}),
    ...(asset.is_publicly_accessible && {is_publicly_accessible: asset.is_publicly_accessible}),
    ...(asset.is_scanned && {is_scanned: asset.is_scanned}),
    ...(asset.is_virtual && {is_virtual: asset.is_virtual}),
    // Hints
    ...(asset.iri && {parent_iri: asset.iri}),
    ...(asset.locations && {locations_iri: asset.locations}),
    ...(asset.external_references && {ext_ref_iri: asset.external_references}),
    ...(asset.notes && {notes_iri: asset.notes}),
    ...(asset.installed_hardware && {installed_hw_iri: asset.installed_hardware}),
    ...(asset.installed_operating_system && {installed_os_iri: asset.installed_operating_system}),
    ...(asset.installed_software && {installed_sw_iri: asset.installed_software}),
    ...(asset.ip_address && {ip_addr_iri: asset.ip_address}),
    ...(asset.mac_address && {mac_addr_iri: asset.mac_address}),
    ...(asset.ports && {ports_iri: asset.ports}),
    ...(asset.connected_to_network && {conn_network_iri: asset.connected_to_network}),
  }
}

export default computingDeviceResolvers;