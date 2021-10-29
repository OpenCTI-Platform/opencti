export function getSparqlQuery( type, id, filter, ) {
  var sparqlQuery;
  let re = /{iri}/g;  // using regex with 'g' switch to replace all instances of a marker
  switch( type ) {
    case 'IPV4-ADDR':
      sparqlQuery = ipAddr.replace("{ipAddrType}", "IpV4Address").replace(re, id);
      break;
    case 'IPV6-ADDR':
      sparqlQuery = ipAddr.replace("{ipAddrType}", "IpV6Address").replace(re, id);
      break;
    case 'MAC-ADDR':
      sparqlQuery = macAddr.replace(re, id)
      break;
    case 'PORT-INFO':
      sparqlQuery = portInfo.replace(re, id)
      break;
    case 'COMPUTING-DEVICE':
      let byId = '';
      let filterStr = '';
      if (id !== undefined) {
        byId = byIdClause.replace("{id}", id);
      }
      // sparqlQuery = selectQueryForm + byId + predicates + inventoryConstraint + filterStr + '}';
      sparqlQuery = selectClause + 
          typeConstraint + 
          byId + 
          predicates + 
          inventoryConstraint + 
          filterStr + '}';
      break;
    default:
      throw new Error(`Unsupported query type ' ${type}'`)
  }

  return sparqlQuery ;
}

export function getReducer( type ) {
  var reducer ;
  switch( type ) {
    case 'COMPUTING-DEVICE':
      reducer = computingDeviceAssetReducer;
      break;
    case 'IPV4-ADDR':
    case 'IPV6-ADDR':
      reducer = ipAddressReducer;
      break;
    case 'MAC-ADDR':
      reducer = macAddressReducer;
      break;
    case 'PORT-INFO':
      reducer = portReducer;
      break;
    default:
      throw new Error(`Unsupported reducer type ' ${type}'`)
  }
  return reducer ;
}


const selectClause = `
SELECT DISTINCT ?iri ?rdf_type ?id
  ?asset_id ?name ?description ?locations
  ?asset_type ?asset_tag ?serial_number ?vendor_name ?version ?release_date
  ?function ?cpe_identifier ?model ?motherboard_id ?installation_id ?installed_hardware ?installed_operating_system 
  ?is_publicly_accessible ?is_scanned ?is_virtual ?bios_id ?fqdn ?hostname ?netbios_name ?network_id ?default_gateway ?vlan_id ?uri ?installed_software ?ip_address ?mac_address ?ports
FROM <tag:stardog:api:context:named>
WHERE {
`;

const bindIRIClause = `\tBIND(<{iri}> AS ?iri)\n`;
const typeConstraint = `\t?iri a <http://scap.nist.gov/ns/asset-identification#ComputingDevice> .\n`;
const byIdClause = `\t?iri <http://darklight.ai/ns/common#id> "{id}" .`;

const predicates = `
?iri <http://darklight.ai/ns/common#id> ?id .
?iri <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> ?rdf_type .
# OPTIONAL { ?iri <http://darklight.ai/ns/common#id> ?id } .
  OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#asset_id> ?asset_id } .
  OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#name> ?name } .
  OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#description> ?description } .
  OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#locations> ?locations } .
  # OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#responsible_parties> ?responsible_party } .
  # ItAsset
  OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#asset_type> ?asset_type } .
  OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#asset_tag> ?asset_tag } .
  OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#serial_number> ?serial_number } .
  OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#vendor_name> ?vendor_name }.
  OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#version> ?version } .
  OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#release_date> ?release_date } .
  # Hardware - ComputingDevice - NetworkDevice
  OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#function> ?function } .
  OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#cpe_identifier> ?cpe_identifier } .
  OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#model> ?model } .
  OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#motherboard_id> ?motherboard_id }
  OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#installation_id> ?installation_id }
  OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#installed_hardware> ?installed_hardware } .
  OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#installed_operating_system> ?installed_operating_system } .
  # ComputingDevice - Server - Workstation
  OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#is_publicly_accessible> ?is_publicly_accessible } .
  OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#is_scanned> ?is_scanned } .
  OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#is_virtual> ?is_virtual } .
  OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#bios_id> ?bios_id }.
  OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#fqdn> ?fqdn } .
  OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#hostname> ?hostname } .
  OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#netbios_name> ?netbios_name } .
  OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#network_id> ?network_id } .
  OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#default_gateway> ?default_gateway } .
  OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#vlan_id> ?vlan_id } .
  OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#uri> ?uri } .
  OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#installed_software> ?installed_software } .
  OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#ip_address> ?ip_address } .
  OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#mac_address> ?mac_address } .
  OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#ports> ?ports } .
`;

const inventoryConstraint = `
  {
      SELECT DISTINCT ?iri
      WHERE {
          ?inventory a <http://csrc.nist.gov/ns/oscal/common#AssetInventory> ;
                <http://csrc.nist.gov/ns/oscal/common#assets> ?iri .
      }
  }` ;

const ipAddr = `SELECT DISTINCT ?rdf_type ?id ?object_type ?ip_address_value ?defanged ?stix_value
FROM <tag:stardog:api:context:named>
WHERE {
    <{iri}> a <http://scap.nist.gov/ns/asset-identification#{ipAddrType}> ;
        <http://darklight.ai/ns/common#id> ?id  ;
        <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> ?rdf_type  ;
        <http://scap.nist.gov/ns/asset-identification#ip_address_value> ?ip_address_value .
    OPTIONAL { <{iri}> <http://darklight.ai/ns/common#object_type> ?object_type } .
    OPTIONAL { <{iri}> <http://docs.oasis-open.org/ns/cti/stix#defanged> ?defanged } .
    OPTIONAL { <{iri}> <http://docs.oasis-open.org/ns/cti/stix/ip-address#value> ?stix_value } .
}`;
const macAddr = `SELECT DISTINCT ?rdf_type ?id ?object_type ?mac_address_value ?is_virtual ?stix_value
FROM <tag:stardog:api:context:named>
WHERE {
    <{iri}> a <http://scap.nist.gov/ns/asset-identification#MACAddress> ;
        <http://darklight.ai/ns/common#id> ?id  ;
        <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> ?rdf_type  ;
        <http://scap.nist.gov/ns/asset-identification#mac_address_value> ?mac_address_value .
    OPTIONAL { <{iri}> <http://scap.nist.gov/ns/asset-identification#is_virtual> ?is_virtual } .
    OPTIONAL { <{iri}> <http://darklight.ai/ns/common#object_type> ?object_type } .
    OPTIONAL { <{iri}> <http://docs.oasis-open.org/ns/cti/stix/ip-address#value> ?stix_value } .
}`;

const portInfo = `SELECT DISTINCT ?rdf_type ?id ?object_type ?port_number ?protocols 
FROM <tag:stardog:api:context:named>
WHERE {
    {iri} a <http://scap.nist.gov/ns/asset-identification#Port> ;
        <http://darklight.ai/ns/common#id> ?id  ;
        <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> ?rdf_type  ;
        <http://scap.nist.gov/ns/asset-identification#port_number> ?port_number ;
        <http://scap.nist.gov/ns/asset-identification#protocols> ?protocols .
    OPTIONAL { {iri} <http://darklight.ai/ns/common#object_type> ?object_type } .
}`;

function computingDeviceAssetReducer( asset ) {
  return {
    id: asset.id,
    ...(asset.created && {created: asset.created}),
    ...(asset.modified && {modified: asset.modified}),
    ...(asset.labels && {labels: asset.labels}),
    ...(asset.name && {name: asset.name} ),
    ...(asset.description && {description: asset.description}),
    ...(asset.asset_id && {asset_id: asset.asset_id}),
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

function ipAddressReducer( item ) {
  return {
    id: item.id,
    ...(item.ip_address_value && {ip_address_value: item.ip_address_value}),
  }
}

function macAddressReducer( item ) {
  return {
    id: item.id,
    ...(item.mac_address_value && {mac_address_value: item.mac_address_value}),
    ...(item.is_virtual !== undefined && {is_virtual: item.is_virtual}),
  }
}

function portReducer( item ) {
  return {
    id: item.id,
    ...(item.port_number && {port_number: item.port_number}),
    ...(item.protocols && {protocols: item.protocols}),
  }
}

