import {v4 as uuid4} from 'uuid';
import {buildSelectVariables, optionalizePredicate, parameterizePredicate} from "../../utils";

export function getSelectSparqlQuery( type, id, filter, ) {
  // TODO: [DL] Need to convert this to the utils.buildSelectVariables() method. No more string replacement strategy
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

export const predicateMap = {
  id: {
    predicate: "<http://darklight.ai/ns/common#id>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "id")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  asset_id: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#asset_id>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "asset_id")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  name: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#name>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "name")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  description: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#description>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "description")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  locations: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#locations>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "locations")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  asset_type: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#asset_type>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "asset_type")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  asset_tag: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#asset_tag>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "asset_tag")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  serial_number: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#serial_number>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "serial_number")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  vendor_name: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#vendor_name>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "vendor_name")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  version: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#version>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "version")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  release_date: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#release_date>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:datetime`: null, this.predicate, "release_date")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  function: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#function>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "function")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  cpe_identifier: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#cpe_identifier>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "cpe_identifier")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  model: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#model>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "model")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  motherboard_id: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#motherboard_id>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "motherboard_id")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  installation_id: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#installation_id>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "installation_id")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  installed_hardware: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#installed_hardware>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "installed_hardware")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  installed_operating_system: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#installed_operating_system>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "installed_operating_system")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  is_publicly_accessible: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#is_publicly_accessible>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}^^xsd:boolean"`: null, this.predicate, "is_publicly_accessible")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  is_scanned: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#is_scanned>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}^^xsd:boolean"`: null, this.predicate, "is_scanned")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  is_virtual: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#is_virtual>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}^^xsd:boolean"`: null, this.predicate, "is_virtual")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  bios_id: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#bios_id>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "bios_id")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  fqdn: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#fqdn>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "fqdn")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  hostname: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#hostname>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "hostname")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  netbios_name: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#netbios_name>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "netbios_name")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  network_id: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#network_id>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "network_id")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  default_gateway: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#default_gateway>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "default_gateway")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  vlan_id: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#vlan_id>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "vlan_id")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  uri: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#uri>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "uri")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  installed_software: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#installed_software>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "installed_software")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  ip_address: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#ip_address>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "ip_address")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  mac_address: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#mac_address>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "mac_address")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  ports: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#ports>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "ports")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  }
}

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
  OPTIONAL { ?iri <http://scap.nist.gov/ns/asset-identification#installation_id> ?installed_operating_system } .
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

export const insertQuery = (propValues) => {
  const id = uuid4();
  const iri = `<http://scap.nist.gov/ns/asset-identification#ComputingDevice-${id}>`;
  const insertPredicates = Object.entries(propValues)
    .filter((propPair) => predicateMap.hasOwnProperty(propPair[0]))
    .map((propPair) => predicateMap[propPair[0]].binding(iri, propPair[1]))
    .join('.\n      ')
  const query = `
  INSERT DATA {
    GRAPH ${iri} {
      ${iri} a <http://scap.nist.gov/ns/asset-identification#ComputingDevice> .
      ${iri} a <http://scap.nist.gov/ns/asset-identification#Hardware> .
      ${iri} a <http://scap.nist.gov/ns/asset-identification#ItAsset> .
      ${iri} a <http://scap.nist.gov/ns/asset-identification#Asset> .
      ${iri} a <http://darklight.ai/ns/common#Object> .
      ${iri} <http://darklight.ai/ns/common#id> "${id}".
      ${insertPredicates}
    }
  }
  `
  return {iri, id, query}
}

const inventoryConstraint = `
  {
      SELECT DISTINCT ?iri
      WHERE {
          ?inventory a <http://csrc.nist.gov/ns/oscal/common#AssetInventory> ;
                <http://csrc.nist.gov/ns/oscal/common#assets> ?iri .
      }
  }` ;

const ipAddr = `SELECT DISTINCT ?id ?object_type ?ip_address_value ?defanged ?stix_value
WHERE {
    GRAPH <{iri}> {
      <{iri}> a <http://scap.nist.gov/ns/asset-identification#{ipAddrType}> ;
          <http://darklight.ai/ns/common#id> ?id  ;
          <http://scap.nist.gov/ns/asset-identification#ip_address_value> ?ip_address_value .
      OPTIONAL { <{iri}> <http://darklight.ai/ns/common#object_type> ?object_type } .
      OPTIONAL { <{iri}> <http://docs.oasis-open.org/ns/cti/stix#defanged> ?defanged } .
      OPTIONAL { <{iri}> <http://docs.oasis-open.org/ns/cti/stix/ip-address#value> ?stix_value } .
    }
}`;
const macAddr = `SELECT DISTINCT ?id ?object_type ?mac_address_value ?is_virtual ?stix_value
WHERE {
    GRAPH <{iri}> {
      <{iri}> a <http://scap.nist.gov/ns/asset-identification#MACAddress> ;
          <http://darklight.ai/ns/common#id> ?id  ;
          <http://scap.nist.gov/ns/asset-identification#mac_address_value> ?mac_address_value .
      OPTIONAL { <{iri}> <http://scap.nist.gov/ns/asset-identification#is_virtual> ?is_virtual } .
      OPTIONAL { <{iri}> <http://darklight.ai/ns/common#object_type> ?object_type } .
      OPTIONAL { <{iri}> <http://docs.oasis-open.org/ns/cti/stix/ip-address#value> ?stix_value } .
    }
}`;

const portInfo = `SELECT DISTINCT ?id ?object_type ?port_number ?protocols 
WHERE {
    GRAPH <{iri}> {
      <{iri}> a <http://scap.nist.gov/ns/asset-identification#Port> ;
          <http://darklight.ai/ns/common#id> ?id  ;
          <http://scap.nist.gov/ns/asset-identification#port_number> ?port_number ;
          <http://scap.nist.gov/ns/asset-identification#protocols> ?protocols .
      OPTIONAL { <{iri}> <http://darklight.ai/ns/common#object_type> ?object_type } .
    }
}`;

export const selectObjectRefsQuery = (id, properties) => {
  const { selectClause ,predicates } = buildSelectVariables(predicateMap, ["ports", "ip_address"])
  const iri = `<http://scap.nist.gov/ns/asset-identification#ComputingDevice-${id}>`
  return `
  SELECT ${selectClause} WHERE {
    GRAPH ${iri} {
       ${iri} a <http://scap.nist.gov/ns/asset-identification#ComputingDevice> .
       ${predicates} 
    }
  }
  `
}

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
    ...(item.port_number && {port_number: item.port_number[0]}),
    ...(item.protocols && {protocols: item.protocols}),
  }
}

