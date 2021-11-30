export function getSelectSparqlQuery( type, id, filter, ) {
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
SELECT DISTINCT ?iri ?id
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

const ipAddr = `SELECT DISTINCT ?id ?object_type ?ip_address_value ?defanged ?stix_value
FROM <tag:stardog:api:context:named>
WHERE {
    <{iri}> a <http://scap.nist.gov/ns/asset-identification#{ipAddrType}> ;
        <http://darklight.ai/ns/common#id> ?id  ;
        <http://scap.nist.gov/ns/asset-identification#ip_address_value> ?ip_address_value .
    OPTIONAL { <{iri}> <http://darklight.ai/ns/common#object_type> ?object_type } .
    OPTIONAL { <{iri}> <http://docs.oasis-open.org/ns/cti/stix#defanged> ?defanged } .
    OPTIONAL { <{iri}> <http://docs.oasis-open.org/ns/cti/stix/ip-address#value> ?stix_value } .
}`;
const macAddr = `SELECT DISTINCT ?id ?object_type ?mac_address_value ?is_virtual ?stix_value
FROM <tag:stardog:api:context:named>
WHERE {
    <{iri}> a <http://scap.nist.gov/ns/asset-identification#MACAddress> ;
        <http://darklight.ai/ns/common#id> ?id  ;
        <http://scap.nist.gov/ns/asset-identification#mac_address_value> ?mac_address_value .
    OPTIONAL { <{iri}> <http://scap.nist.gov/ns/asset-identification#is_virtual> ?is_virtual } .
    OPTIONAL { <{iri}> <http://darklight.ai/ns/common#object_type> ?object_type } .
    OPTIONAL { <{iri}> <http://docs.oasis-open.org/ns/cti/stix/ip-address#value> ?stix_value } .
}`;

const portInfo = `SELECT DISTINCT ?id ?object_type ?port_number ?protocols 
FROM <tag:stardog:api:context:named>
WHERE {
    {iri} a <http://scap.nist.gov/ns/asset-identification#Port> ;
        <http://darklight.ai/ns/common#id> ?id  ;
        <http://scap.nist.gov/ns/asset-identification#port_number> ?port_number ;
        <http://scap.nist.gov/ns/asset-identification#protocols> ?protocols .
    OPTIONAL { {iri} <http://darklight.ai/ns/common#object_type> ?object_type } .
}`;

function computingDeviceAssetReducer( item ) {
  // this code is to work around an issue in the data where we sometimes get multiple operatings
  // when there shouldn't be but just one
  if (Array.isArray( item.installed_operating_system )  && item.installed_operating_system.length > 0 ) {
    if (item.installed_operating_system.length > 1) {
      console.log(`[INFO] ${item.iri} (${item.id}) has ${item.installed_operating_system.length} values: ${item.installed_operating_system}`)
    }
    item.installed_operating_system = item.installed_operating_system[0]
  }

  // if no object type was returned, compute the type from the IRI
  if ( item.object_type === undefined && item.asset_type !== undefined ) {
    item.object_type = item.asset_type
  } else {
    item.object_type = 'computing-device';
  }
  
  return {
    id: item.id,
    ...(item.object_type && {entity_type: item.object_type}),
    ...(item.created && {created: item.created}),
    ...(item.modified && {modified: item.modified}),
    ...(item.labels && {labels: item.labels}),
    ...(item.name && {name: item.name} ),
    ...(item.description && {description: item.description}),
    ...(item.asset_id && {asset_id: item.asset_id}),
    // ItAsset
    ...(item.asset_type && {asset_type: item.asset_type}),
    ...(item.asset_tag && {asset_tag: item.asset_tag}) ,
    ...(item.serial_number && {serial_number: item.serial_number}),
    ...(item.vendor_name && {vendor_name: item.vendor_name}),
    ...(item.version && {version: item.version}),
    ...(item.release_date && {release_date: item.release_date}),
    // Hardware
    ...(item.function && {function: item.function}),
    ...(item.cpe_identifier && {cpe_identifier: item.cpe_identifier}),
    ...(item.installation_id && {installation_id: item.installation_id}),
    ...(item.model && {model: item.model}),
    ...(item.motherboard_id && {motherboard_id: item.motherboard_id}),
    ...(item.baseline_configuration_name && {baseline_configuration_name: item.baseline_configuration_name}),
    // ComputingDevice
    ...(item.bios_id && {bios_id: item.bios_id}),
    ...(item.network_id && {network_id: item.network_id}),
    ...(item.vlan_id && {vlan_id: item.vlan_id}),
    ...(item.default_gateway && {default_gateway: item.default_gateway}),
    ...(item.fqdn && {fqdn: item.fqdn}),
    ...(item.hostname && {hostname: item.hostname}),
    ...(item.netbios_name && {netbios_name: item.netbios_name}),
    ...(item.uri && {uri: item.uri}),
    ...(item.is_publicly_accessible && {is_publicly_accessible: item.is_publicly_accessible}),
    ...(item.is_scanned && {is_scanned: item.is_scanned}),
    ...(item.is_virtual && {is_virtual: item.is_virtual}),
    // Hints
    ...(item.iri && {parent_iri: item.iri}),
    ...(item.locations && {locations_iri: item.locations}),
    ...(item.external_references && {ext_ref_iri: item.external_references}),
    ...(item.notes && {notes_iri: item.notes}),
    ...(item.installed_hardware && {installed_hw_iri: item.installed_hardware}),
    ...(item.installed_operating_system && {installed_os_iri: item.installed_operating_system}),
    ...(item.installed_software && {installed_sw_iri: item.installed_software}),
    ...(item.ip_address && {ip_addr_iri: item.ip_address}),
    ...(item.mac_address && {mac_addr_iri: item.mac_address}),
    ...(item.ports && {ports_iri: item.ports}),
    ...(item.connected_to_network && {conn_network_iri: item.connected_to_network}),
  }
}

function ipAddressReducer( item ) {
  return {
    id: item.id,
    ...(item.object_type && {entity_type: item.object_type}),
    ...(item.ip_address_value && {ip_address_value: item.ip_address_value}),
  }
}

function macAddressReducer( item ) {
  return {
    id: item.id,
    ...(item.object_type && {entity_type: item.object_type}),
    ...(item.mac_address_value && {mac_address_value: item.mac_address_value}),
    ...(item.is_virtual !== undefined && {is_virtual: item.is_virtual}),
  }
}

function portReducer( item ) {
  return {
    id: item.id,
    ...(item.object_type && {entity_type: item.object_type}),
    ...(item.port_number && {port_number: item.port_number}),
    ...(item.protocols && {protocols: item.protocols}),
  }
}

