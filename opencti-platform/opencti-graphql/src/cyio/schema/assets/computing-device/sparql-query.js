import {
  buildSelectVariables,
  optionalizePredicate,
  parameterizePredicate,
  generateId,
  OASIS_SCO_NS,
} from '../../utils.js';

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
const predicateBody = `
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
  }`;
const ipAddr = `
  SELECT DISTINCT ?id ?object_type ?ip_address_value ?defanged ?stix_value
  FROM <tag:stardog:api:context:named>
  WHERE {
    <{iri}> a <http://scap.nist.gov/ns/asset-identification#{ipAddrType}> ;
        <http://darklight.ai/ns/common#id> ?id  ;
        <http://scap.nist.gov/ns/asset-identification#ip_address_value> ?ip_address_value .
    OPTIONAL { <{iri}> <http://darklight.ai/ns/common#object_type> ?object_type } .
    OPTIONAL { <{iri}> <http://docs.oasis-open.org/ns/cti/stix#defanged> ?defanged } .
    OPTIONAL { <{iri}> <http://docs.oasis-open.org/ns/cti/stix/ip-address#value> ?stix_value } .
  }`;
const macAddr = `
  SELECT DISTINCT ?iri ?id ?object_type ?mac_address_value ?is_virtual ?stix_value
  FROM <tag:stardog:api:context:named>
  WHERE {
    <{iri}> a <http://scap.nist.gov/ns/asset-identification#MACAddress> ;
        <http://darklight.ai/ns/common#id> ?id  ;
        <http://scap.nist.gov/ns/asset-identification#mac_address_value> ?mac_address_value .
    OPTIONAL { <{iri}> <http://scap.nist.gov/ns/asset-identification#is_virtual> ?is_virtual } .
    OPTIONAL { <{iri}> <http://darklight.ai/ns/common#object_type> ?object_type } .
    OPTIONAL { <{iri}> <http://docs.oasis-open.org/ns/cti/stix/ip-address#value> ?stix_value } .
  }`;
const portInfo = `
  SELECT DISTINCT ?id ?object_type ?port_number ?protocols 
  FROM <tag:stardog:api:context:named>
  WHERE {
    <{iri}> a <http://scap.nist.gov/ns/asset-identification#Port> ;
        <http://darklight.ai/ns/common#id> ?id  ;
        <http://scap.nist.gov/ns/asset-identification#port_number> ?port_number ;
        <http://scap.nist.gov/ns/asset-identification#protocols> ?protocols .
    OPTIONAL { <{iri}> <http://darklight.ai/ns/common#object_type> ?object_type } .
  }`;

export function getReducer(type) {
  switch (type) {
    case 'COMPUTING-DEVICE':
      return computingDeviceAssetReducer;
    case 'IPV4-ADDR':
    case 'IPV6-ADDR':
      return ipAddressReducer;
    case 'MAC-ADDR':
      return macAddressReducer;
    case 'PORT-INFO':
      return portReducer;
    default:
      throw new Error(`Unsupported reducer type ' ${type}'`);
  }
}

// Reducers
export const computingDeviceAssetReducer = (item) => {
  // this code is to work around an issue in the data where we sometimes get multiple operating systems
  // when there shouldn't be but just one
  if ('installed_operating_system' in item) {
    if (Array.isArray(item.installed_operating_system) && item.installed_operating_system.length > 0) {
      if (item.installed_operating_system.length > 1) {
        console.log(
          `[CYIO] CONSTRAINT-VIOLATION: ${item.iri} 'installed_operating_system' violates maxCount constraint`
        );
      }
      item.installed_operating_system = item.installed_operating_system[0];
    }
  }

  // if no object type was returned, compute the type from the IRI
  if (item.object_type === undefined && item.asset_type !== undefined) {
    if (item.asset_type == 'compute-device') {
      item.asset_type = 'computing-device';
      item.object_type = 'computing-device';
    } else {
      if (item.asset_type.includes('_')) item.asset_type = item.asset_type.replace(/_/g, '-');
      item.object_type = item.asset_type;
    }
  } else {
    item.object_type = 'computing-device';
  }

  return {
    iri: item.iri,
    id: item.id,
    standard_id: item.id,
    ...(item.object_type && { entity_type: item.object_type }),
    ...(item.created && { created: item.created }),
    ...(item.modified && { modified: item.modified }),
    ...(item.name && { name: item.name }),
    ...(item.description && { description: item.description }),
    ...(item.asset_id && { asset_id: item.asset_id }),
    // ItAsset
    ...(item.asset_type && { asset_type: item.asset_type }),
    ...(item.asset_tag && { asset_tag: item.asset_tag }),
    ...(item.serial_number && { serial_number: item.serial_number }),
    ...(item.vendor_name && { vendor_name: item.vendor_name }),
    ...(item.version && { version: item.version }),
    ...(item.release_date && { release_date: item.release_date }),
    ...(item.operational_status && { operational_status: item.operational_status }),
    ...(item.implementation_point && { implementation_point: item.implementation_point }),
    // Hardware
    ...(item.function && { function: item.function }),
    ...(item.cpe_identifier && { cpe_identifier: item.cpe_identifier }),
    ...(item.installation_id && { installation_id: item.installation_id }),
    ...(item.model && { model: item.model }),
    ...(item.motherboard_id && { motherboard_id: item.motherboard_id }),
    ...(item.baseline_configuration_name && { baseline_configuration_name: item.baseline_configuration_name }),
    // ComputingDevice
    ...(item.bios_id && { bios_id: item.bios_id }),
    ...(item.network_id && { network_id: item.network_id }),
    ...(item.vlan_id && { vlan_id: item.vlan_id }),
    ...(item.default_gateway && { default_gateway: item.default_gateway }),
    ...(item.fqdn && { fqdn: item.fqdn }),
    ...(item.hostname && { hostname: item.hostname }),
    ...(item.netbios_name && { netbios_name: item.netbios_name }),
    ...(item.uri && { uri: item.uri }),
    ...(item.is_publicly_accessible !== undefined && { is_publicly_accessible: item.is_publicly_accessible }),
    ...(item.is_scanned !== undefined && { is_scanned: item.is_scanned }),
    ...(item.is_virtual !== undefined && { is_virtual: item.is_virtual }),
    ...(item.last_scanned && { last_scanned: item.last_scanned }),
    // Hints
    ...(item.iri && { parent_iri: item.iri }),
    ...(item.locations && { locations_iri: item.locations }),
    ...(item.external_references && { ext_ref_iri: item.external_references }),
    ...(item.labels && { labels_iri: item.labels }),
    ...(item.notes && { notes_iri: item.notes }),
    ...(item.installed_hardware && { installed_hw_iri: item.installed_hardware }),
    ...(item.installed_operating_system && { installed_os_iri: item.installed_operating_system }),
    ...(item.installed_software && { installed_sw_iri: item.installed_software }),
    ...(item.ip_address && { ip_addr_iri: item.ip_address }),
    ...(item.mac_address && { mac_addr_iri: item.mac_address }),
    ...(item.ports && { ports_iri: item.ports }),
    ...(item.connected_to_network && { conn_network_iri: item.connected_to_network }),
    ...(item.responsible_parties && { responsible_party_iris: item.responsible_parties }),
  };
};
export const ipAddressReducer = (item) => {
  if (item.object_type === undefined || item.object_type == null) {
    item.ip_address_value.includes(':') ? (item.object_type = 'ipv6-addr') : (item.object_type = 'ipv4-addr');
  }

  return {
    id: item.id,
    standard_id: item.id,
    ...(item.object_type && { entity_type: item.object_type }),
    ...(item.created && { created: item.created }),
    ...(item.modified && { modified: item.modified }),
    ...(item.ip_address_value && { ip_address_value: item.ip_address_value }),
    // Hints
    ...(item.iri && { parent_iri: item.iri }),
  };
};
export const macAddressReducer = (item) => {
  // if no object type was returned, compute the type from the IRI
  if (item.object_type === undefined || item.object_type == null) item.object_type = 'mac-addr';
  return {
    id: item.id,
    standard_id: item.id,
    ...(item.object_type && { entity_type: item.object_type }),
    ...(item.created && { created: item.created }),
    ...(item.modified && { modified: item.modified }),
    ...(item.mac_address_value && { mac_address_value: item.mac_address_value }),
    ...(item.is_virtual !== undefined && { is_virtual: item.is_virtual }),
    // Hints
    ...(item.iri && { parent_iri: item.iri }),
  };
};
export const portReducer = (item) => {
  // if no object type was returned, compute the type from the IRI
  if (item.object_type === undefined || item.object_type == null) item.object_type = 'port';
  return {
    id: item.id,
    standard_id: item.id,
    ...(item.object_type && { entity_type: item.object_type }),
    ...(item.created && { created: item.created }),
    ...(item.modified && { modified: item.modified }),
    ...(item.port_number && { port_number: item.port_number }),
    ...(item.protocols && { protocols: item.protocols }),
    // Hints
    ...(item.iri && { parent_iri: item.iri }),
  };
};

// ComputingDevice resolver support functions
export function getSelectSparqlQuery(type, select, id, args) {
  // TODO: [DL] Need to convert this to the utils.buildSelectVariables() method. No more string replacement strategy
  let sparqlQuery;

  // Adjust select to deal with difference between ontology and GraphQL object definition
  if (type == 'COMPUTING-DEVICE' && select !== null) {
    select = select.filter((i) => i !== 'ipv4_address');
    select = select.filter((i) => i !== 'ipv6_address');
    select.push('ip_address');
  }
  if (select === undefined || select === null) select = Object.keys(computingDevicePredicateMap);
  if (!select.includes('id')) select.push('id');

  if (args !== undefined) {
    if (args.filters !== undefined && id === undefined) {
      for (const filter of args.filters) {
        if (!select.includes(filter.key)) select.push(filter.key);
      }
    }

    // add value of orderedBy's key to cause special predicates to be included
    if (args.orderedBy !== undefined) {
      if (!select.includes(args.orderedBy)) select.push(args.orderedBy);
    }
  }

  let { selectionClause, predicates } = buildSelectVariables(computingDevicePredicateMap, select);
  selectionClause = `SELECT ${select.includes('id') ? 'DISTINCT ?iri' : '?iri'} ${selectionClause}`;
  const selectPortion = `
${selectionClause}
FROM <tag:stardog:api:context:named>
WHERE {
  `;
  const re = /{iri}/g; // using regex with 'g' switch to replace all instances of a marker
  switch (type) {
    case 'COMPUTING-DEVICE':
      let byId = '';
      const filterStr = '';
      if (id !== undefined) {
        byId = byIdClause.replace('{id}', id);
      }
      sparqlQuery = `${selectPortion + typeConstraint + byId + predicates + inventoryConstraint + filterStr}}`;
      break;
    case 'IPV4-ADDR':
      sparqlQuery = ipAddr.replace('{ipAddrType}', 'IpV4Address').replace(re, id);
      break;
    case 'IPV6-ADDR':
      sparqlQuery = ipAddr.replace('{ipAddrType}', 'IpV6Address').replace(re, id);
      break;
    case 'MAC-ADDR':
      sparqlQuery = `${selectPortion + bindIRIClause.replace('{iri}', id) + predicates}\n}`;
      break;
    case 'PORT-INFO':
      sparqlQuery = portInfo.replace(re, id);
      break;
    default:
      throw new Error(`Unsupported query type ' ${type}'`);
  }

  return sparqlQuery;
}
export const insertQuery = (propValues) => {
  const id_material = {
    ...(propValues.name && { name: propValues.name }),
    ...(propValues.cpe_identifier && { cpe: propValues.cpe_identifier }),
    ...(propValues.vendor_name && { vendor: propValues.vendor_name }),
    ...(propValues.version && { version: propValues.version }),
  };
  const id = generateId(id_material, OASIS_SCO_NS);
  const timestamp = new Date().toISOString();

  // escape any special characters (e.g., newline)
  if (propValues.description !== undefined) {
    if (propValues.description.includes('\n')) propValues.description = propValues.description.replace(/\n/g, '\\n');
    if (propValues.description.includes('"')) propValues.description = propValues.description.replace(/\"/g, '\\"');
    if (propValues.description.includes("'")) propValues.description = propValues.description.replace(/\'/g, "\\'");
  }

  const iri = `<http://scap.nist.gov/ns/asset-identification#Hardware-${id}>`;
  const insertPredicates = Object.entries(propValues)
    .filter((propPair) => computingDevicePredicateMap.hasOwnProperty(propPair[0]))
    .map((propPair) => computingDevicePredicateMap[propPair[0]].binding(iri, propPair[1]))
    .join('.\n      ');
  const query = `
  INSERT DATA {
    GRAPH ${iri} {
      ${iri} a <http://csrc.nist.gov/ns/oscal/common#InventoryItem> .
      ${iri} a <http://scap.nist.gov/ns/asset-identification#ComputingDevice> .
      ${iri} a <http://scap.nist.gov/ns/asset-identification#Hardware> .
      ${iri} a <http://scap.nist.gov/ns/asset-identification#ItAsset> .
      ${iri} a <http://scap.nist.gov/ns/asset-identification#Asset> .
      ${iri} a <http://darklight.ai/ns/common#Object> .
      ${iri} <http://darklight.ai/ns/common#id> "${id}".
      ${iri} <http://darklight.ai/ns/common#object_type> "computing-device" . 
      ${iri} <http://darklight.ai/ns/common#created> "${timestamp}"^^xsd:dateTime . 
      ${iri} <http://darklight.ai/ns/common#modified> "${timestamp}"^^xsd:dateTime . 
      ${insertPredicates}
    }
  }
  `;
  return { iri, id, query };
};
export const selectObjectRefsQuery = (id, _properties) => {
  const { selectClause, predicates } = buildSelectVariables(computingDevicePredicateMap, ['ports', 'ip_address']);
  const iri = `<http://scap.nist.gov/ns/asset-identification#Hardware-${id}>`;
  return `
  SELECT ${selectClause} 
  FROM <tag:stardog:api:context:named>
  WHERE {
      ${iri} a <http://scap.nist.gov/ns/asset-identification#ComputingDevice> .
      ${predicates} 
  }`;
};
// TODO: Update resolvers to utilize these functions in place of the above; delete the above
export const insertComputingDeviceQuery = (propValues) => {
  const id_material = {
    ...(propValues.name && { name: propValues.name }),
    ...(propValues.cpe_identifier && { cpe: propValues.cpe_identifier }),
    ...(propValues.vendor_name && { vendor: propValues.vendor_name }),
    ...(propValues.version && { version: propValues.version }),
  };
  const id = generateId(id_material, OASIS_SCO_NS);
  const timestamp = new Date().toISOString();

  // escape any special characters (e.g., newline)
  if (propValues.description !== undefined) {
    if (propValues.description.includes('\n')) propValues.description = propValues.description.replace(/\n/g, '\\n');
    if (propValues.description.includes('"')) propValues.description = propValues.description.replace(/\"/g, '\\"');
    if (propValues.description.includes("'")) propValues.description = propValues.description.replace(/\'/g, "\\'");
  }

  const iri = `<http://scap.nist.gov/ns/asset-identification#Hardware-${id}>`;
  const insertPredicates = Object.entries(propValues)
    .filter((propPair) => computingDevicePredicateMap.hasOwnProperty(propPair[0]))
    .map((propPair) => computingDevicePredicateMap[propPair[0]].binding(iri, propPair[1]))
    .join('.\n      ');
  const query = `
  INSERT DATA {
    GRAPH ${iri} {
      ${iri} a <http://csrc.nist.gov/ns/oscal/common#InventoryItem> .
      ${iri} a <http://scap.nist.gov/ns/asset-identification#ComputingDevice> .
      ${iri} a <http://scap.nist.gov/ns/asset-identification#Hardware> .
      ${iri} a <http://scap.nist.gov/ns/asset-identification#ItAsset> .
      ${iri} a <http://scap.nist.gov/ns/asset-identification#Asset> .
      ${iri} a <http://darklight.ai/ns/common#Object> . 
      ${iri} <http://darklight.ai/ns/common#id> "${id}" .
      ${iri} <http://darklight.ai/ns/common#object_type> "computing-device" . 
      ${iri} <http://darklight.ai/ns/common#created> "${timestamp}"^^xsd:dateTime . 
      ${iri} <http://darklight.ai/ns/common#modified> "${timestamp}"^^xsd:dateTime . 
      ${insertPredicates}
    }
  }
  `;
  return { iri, id, query };
};
export const selectComputingDeviceQuery = (id, select) => {
  return selectComputingDeviceByIriQuery(`http://scap.nist.gov/ns/asset-identification#Hardware-${id}`, select);
};
export const selectComputingDeviceByIriQuery = (iri, select) => {
  if (!iri.startsWith('<')) iri = `<${iri}>`;
  if (select === undefined || select === null) select = Object.keys(computingDevicePredicateMap);
  const { selectionClause, predicates } = buildSelectVariables(computingDevicePredicateMap, select);
  return `
  SELECT ?iri ${selectionClause}
  FROM <tag:stardog:api:context:local>
  WHERE {
    BIND(${iri} AS ?iri)
    ?iri a <http://scap.nist.gov/ns/asset-identification#ComputingDevice> .
    ${predicates}
  }
  `;
};
export const selectAllComputingDevices = (select, args) => {
  if (select === undefined || select === null) select = Object.keys(computingDevicePredicateMap);
  if (!select.includes('id')) select.push('id');

  if (args !== undefined) {
    if (args.filters !== undefined) {
      for (const filter of args.filters) {
        if (!select.includes(filter.key)) select.push(filter.key);
      }
    }

    // add value of orderedBy's key to cause special predicates to be included
    if (args.orderedBy !== undefined) {
      if (!select.includes(args.orderedBy)) select.push(args.orderedBy);
    }
  }

  const { selectionClause, predicates } = buildSelectVariables(computingDevicePredicateMap, select);
  return `
  SELECT DISTINCT ?iri ${selectionClause} 
  FROM <tag:stardog:api:context:local>
  WHERE {
    ?iri a <http://scap.nist.gov/ns/asset-identification#ComputingDevice> . 
    ${predicates}
  }
  `;
};
export const deleteComputingDeviceQuery = (id) => {
  const iri = `http://scap.nist.gov/ns/asset-identification#Hardware-${id}`;
  return deleteComputingDeviceByIriQuery(iri);
};
export const deleteComputingDeviceByIriQuery = (iri) => {
  return `
  DELETE {
    GRAPH <${iri}> {
      ?iri ?p ?o
    }
  } WHERE {
    GRAPH <${iri}> {
      ?iri a <http://scap.nist.gov/ns/asset-identification#ComputingDevice> .
      ?iri ?p ?o
    }
  }
  `;
};
export const attachToComputingDeviceQuery = (id, field, itemIris) => {
  const iri = `<http://scap.nist.gov/ns/asset-identification#Hardware-${id}>`;
  if (!computingDevicePredicateMap.hasOwnProperty(field)) return null;
  const { predicate } = computingDevicePredicateMap[field];
  let statements;
  if (Array.isArray(itemIris)) {
    statements = itemIris.map((itemIri) => `${iri} ${predicate} ${itemIri}`).join('.\n        ');
  } else {
    statements = `${iri} ${predicate} ${itemIris}`;
  }
  return `
  INSERT DATA {
    GRAPH ${iri} {
      ${statements}
    }
  }
  `;
};
export const detachFromComputingDeviceQuery = (id, field, itemIris) => {
  const iri = `<http://scap.nist.gov/ns/asset-identification#Hardware-${id}>`;
  if (!computingDevicePredicateMap.hasOwnProperty(field)) return null;
  const { predicate } = computingDevicePredicateMap[field];
  let statements;
  if (Array.isArray(itemIris)) {
    statements = itemIris.map((itemIri) => `${iri} ${predicate} ${itemIri}`).join('.\n        ');
  } else {
    statements = `${iri} ${predicate} ${itemIris}`;
  }
  return `
  DELETE DATA {
    GRAPH ${iri} {
      ${statements}
    }
  }
  `;
};

// Predicate Maps
export const computingDevicePredicateMap = {
  id: {
    predicate: '<http://darklight.ai/ns/common#id>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'id');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  object_type: {
    predicate: '<http://darklight.ai/ns/common#object_type>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'object_type');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  created: {
    predicate: '<http://darklight.ai/ns/common#created>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime` : null, this.predicate, 'created');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  modified: {
    predicate: '<http://darklight.ai/ns/common#modified>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime` : null, this.predicate, 'modified');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  labels: {
    predicate: '<http://darklight.ai/ns/common#labels>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'labels');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  label_name: {
    predicate: '<http://darklight.ai/ns/common#labels>/<http://darklight.ai/ns/common#name>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'label_name');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  notes: {
    predicate: '<http://darklight.ai/ns/common#notes>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'notes');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  external_references: {
    predicate: '<http://darklight.ai/ns/common#external_references>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'external_references');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  asset_id: {
    predicate: '<http://scap.nist.gov/ns/asset-identification#asset_id>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'asset_id');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  name: {
    predicate: '<http://scap.nist.gov/ns/asset-identification#name>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'name');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  description: {
    predicate: '<http://scap.nist.gov/ns/asset-identification#description>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'description');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  locations: {
    predicate: '<http://scap.nist.gov/ns/asset-identification#locations>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'locations');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  location_name: {
    predicate: '<http://scap.nist.gov/ns/asset-identification#locations>/<http://darklight.ai/ns/common#name>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'location_name');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  asset_type: {
    predicate: '<http://scap.nist.gov/ns/asset-identification#asset_type>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'asset_type');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  asset_tag: {
    predicate: '<http://scap.nist.gov/ns/asset-identification#asset_tag>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'asset_tag');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  serial_number: {
    predicate: '<http://scap.nist.gov/ns/asset-identification#serial_number>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'serial_number');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  vendor_name: {
    predicate: '<http://scap.nist.gov/ns/asset-identification#vendor_name>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'vendor_name');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  version: {
    predicate: '<http://scap.nist.gov/ns/asset-identification#version>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'version');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  release_date: {
    predicate: '<http://scap.nist.gov/ns/asset-identification#release_date>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime` : null, this.predicate, 'release_date');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  implementation_point: {
    predicate: '<http://scap.nist.gov/ns/asset-identification#implementation_point>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'implementation_point');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  operational_status: {
    predicate: '<http://scap.nist.gov/ns/asset-identification#operational_status>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'operational_status');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  function: {
    predicate: '<http://scap.nist.gov/ns/asset-identification#function>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'function');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  cpe_identifier: {
    predicate: '<http://scap.nist.gov/ns/asset-identification#cpe_identifier>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'cpe_identifier');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  model: {
    predicate: '<http://scap.nist.gov/ns/asset-identification#model>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'model');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  motherboard_id: {
    predicate: '<http://scap.nist.gov/ns/asset-identification#motherboard_id>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'motherboard_id');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  installation_id: {
    predicate: '<http://scap.nist.gov/ns/asset-identification#installation_id>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'installation_id');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  installed_hardware: {
    predicate: '<http://scap.nist.gov/ns/asset-identification#installed_hardware>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'installed_hardware');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  installed_operating_system: {
    predicate: '<http://scap.nist.gov/ns/asset-identification#installed_operating_system>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'installed_operating_system');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  installed_os_name: {
    predicate:
      '<http://scap.nist.gov/ns/asset-identification#installed_operating_system>/<http://scap.nist.gov/ns/asset-identification#name>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'installed_os_name');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  is_publicly_accessible: {
    predicate: '<http://scap.nist.gov/ns/asset-identification#is_publicly_accessible>',
    binding(iri, value) {
      return parameterizePredicate(
        iri,
        value !== undefined ? `"${value}"^^xsd:boolean` : null,
        this.predicate,
        'is_publicly_accessible'
      );
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  is_scanned: {
    predicate: '<http://scap.nist.gov/ns/asset-identification#is_scanned>',
    binding(iri, value) {
      return parameterizePredicate(
        iri,
        value !== undefined ? `"${value}"^^xsd:boolean` : null,
        this.predicate,
        'is_scanned'
      );
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  is_virtual: {
    predicate: '<http://scap.nist.gov/ns/asset-identification#is_virtual>',
    binding(iri, value) {
      return parameterizePredicate(
        iri,
        value !== undefined ? `"${value}"^^xsd:boolean` : null,
        this.predicate,
        'is_virtual'
      );
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  last_scanned: {
    predicate: '<http://scap.nist.gov/ns/asset-identification#last_scanned>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime` : null, this.predicate, 'last_scanned');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  bios_id: {
    predicate: '<http://scap.nist.gov/ns/asset-identification#bios_id>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'bios_id');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  fqdn: {
    predicate: '<http://scap.nist.gov/ns/asset-identification#fqdn>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'fqdn');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  hostname: {
    predicate: '<http://scap.nist.gov/ns/asset-identification#hostname>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'hostname');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  netbios_name: {
    predicate: '<http://scap.nist.gov/ns/asset-identification#netbios_name>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'netbios_name');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  network_id: {
    predicate: '<http://scap.nist.gov/ns/asset-identification#network_id>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'network_id');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  default_gateway: {
    predicate: '<http://scap.nist.gov/ns/asset-identification#default_gateway>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'default_gateway');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  vlan_id: {
    predicate: '<http://scap.nist.gov/ns/asset-identification#vlan_id>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'vlan_id');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  uri: {
    predicate: '<http://scap.nist.gov/ns/asset-identification#uri>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"^^xsd:anyURI` : null, this.predicate, 'uri');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  installed_software: {
    predicate: '<http://scap.nist.gov/ns/asset-identification#installed_software>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'installed_software');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  ip_address: {
    predicate: '<http://scap.nist.gov/ns/asset-identification#ip_address>', // this should really be ipv4_address in ontology
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'ip_address');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  ipv4_address: {
    predicate: '<http://scap.nist.gov/ns/asset-identification#ip_address>', // this should really be ipv4_address in ontology
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'ip4_address');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  ipv6_address: {
    predicate: '<http://scap.nist.gov/ns/asset-identification#ip_address>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'ip6_address');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  mac_address: {
    predicate: '<http://scap.nist.gov/ns/asset-identification#mac_address>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'mac_address');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  mac_address_value: {
    predicate: '<http://scap.nist.gov/ns/asset-identification#mac_address_value>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'mac_address_value');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  ports: {
    predicate: '<http://scap.nist.gov/ns/asset-identification#ports>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'ports');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  connected_to_network: {
    predicate: '<http://scap.nist.gov/ns/asset-identification#connected_to_network>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'connected_to_network');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  baseline_configuration_name: {
    predicate: '<http://scap.nist.gov/ns/asset-identification#baseline_configuration_name>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'baseline_configuration_name');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  responsible_parties: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#responsible_parties>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "responsible_parties");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
};
