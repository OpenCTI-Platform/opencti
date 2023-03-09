import {
  buildSelectVariables, optionalizePredicate, parameterizePredicate,
  generateId, OASIS_SCO_NS, CyioError
} from "../../utils.js";
import {
  ipAddressReducer,
  macAddressReducer,
  portReducer
} from '../computing-device/sparql-query.js';
import { objectMap } from '../../global/global-utils';

export function getReducer(type) {
  switch (type) {
    case 'HARDWARE-DEVICE':
      return hardwareAssetReducer;
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
const hardwareAssetReducer = (item) => {
  // if no object type was returned, compute the type from the asset type and/or the IRI
  if (item.object_type === undefined) {
    if (item.asset_type !== undefined) {
      if (item.asset_type.includes('_')) item.asset_type = item.asset_type.replace(/_/g, '-');
      if (item.asset_type == 'compute-device') item.asset_type = 'computing-device';
      if (item.asset_type in objectMap) item.object_type = 'hardware';
    }
    if (item.object_type === undefined && item.iri !== undefined) {
      if (item.iri.includes('Hardware')) item.object_type = 'hardware';
    }
    if (item.object_type === undefined || item.object_type !== 'hardware') return null;
  }

  // WORKAROUND: this code is to work around an issue in the data where we sometimes get multiple operating systems
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
    ...(item.related_risks && { related_risks_iri: item.related_risks }),
    ...(item.risk_count !== undefined && { risk_count: item.risk_count }),
    ...(item.risk_score !== undefined && { risk_score: item.risk_score }),
    ...(item.top_risk_severity && { top_risk_severity: item.top_risk_severity }),
  };
};

// Hardware resolver support functions
export const insertHardwareQuery = (propValues) => {
  const id_material = {
    ...(propValues.name && { name: propValues.name }),
    ...(propValues.cpe_identifier && { cpe: propValues.cpe_identifier }),
    ...(propValues.vendor_name && { vendor: propValues.vendor_name }),
    ...(propValues.version && { version: propValues.version }),
  };
  const id = generateId(id_material, OASIS_SCO_NS);
  const timestamp = new Date().toISOString();

  if (!objectMap.hasOwnProperty(propValues.asset_type)) throw new CyioError(`Unsupported hardware type ' ${propValues.asset_type}'`);

  // escape any special characters (e.g., newline)
  if (propValues.description !== undefined) {
    if (propValues.description.includes('\n')) propValues.description = propValues.description.replace(/\n/g, '\\n');
    if (propValues.description.includes('"')) propValues.description = propValues.description.replace(/\"/g, '\\"');
    if (propValues.description.includes("'")) propValues.description = propValues.description.replace(/\'/g, "\\'");
  }

  // Fix '_' to '-' in asset_type
  if (propValues.asset_type !== undefined) {
    if (propValues.asset_type.includes('_')) propValues.asset_type = propValues.asset_type.replace(/_/g, '-');
  }

  const iri = `<http://scap.nist.gov/ns/asset-identification#Hardware-${id}>`;
  const selectPredicates = Object.entries(propValues)
    .filter((propPair) => hardwarePredicateMap.hasOwnProperty(propPair[0]))
    .map((propPair) => hardwarePredicateMap[propPair[0]].binding(iri, propPair[1]))
    .join('.\n      ');
  const insertPredicates = [];
  insertPredicates.push(`${iri} a <http://csrc.nist.gov/ns/oscal/common#InventoryItem> `);
  if (propValues.asset_type !== 'hardware') {
    insertPredicates.push(`${iri} a <${objectMap[propValues.asset_type].classIri}>`);
    if (objectMap[propValues.asset_type].parent !== undefined && objectMap[propValues.asset_type].parent !== 'hardware') {
      let parent = objectMap[propValues.asset_type].parent;
      insertPredicates.push(`${iri} a <${objectMap[parent].classIri}>`);
    }
  }
  insertPredicates.push(`${iri} a <http://scap.nist.gov/ns/asset-identification#Hardware> `);
  insertPredicates.push(`${iri} a <http://scap.nist.gov/ns/asset-identification#ItAsset> `);
  insertPredicates.push(`${iri} a <http://scap.nist.gov/ns/asset-identification#Asset> `);
  insertPredicates.push(`${iri} a <http://darklight.ai/ns/common#Object> `);
  insertPredicates.push(`${iri} <http://darklight.ai/ns/common#id> "${id}" `);
  insertPredicates.push(`${iri} <http://darklight.ai/ns/common#object_type> "${propValues.asset_type}" `);
  insertPredicates.push(`${iri} <http://darklight.ai/ns/common#created> "${timestamp}"^^xsd:dateTime `);
  insertPredicates.push(`${iri} <http://darklight.ai/ns/common#modified> "${timestamp}"^^xsd:dateTime `);
  const query = `
  INSERT DATA {
    GRAPH ${iri} {
      ${insertPredicates.join('.\n        ')} .
      ${selectPredicates} .
    }
  }`;

  return { iri, id, query };
};
export const selectHardwareQuery = (id, select) => {
  return selectHardwareByIriQuery(`http://scap.nist.gov/ns/asset-identification#Hardware-${id}`, select);
};
export const selectHardwareByIriQuery = (iri, select) => {
  if (!iri.startsWith('<')) iri = `<${iri}>`;
  if (select != null) {
    if (select.includes('ipv4_address') || select.includes('ipv6_address')) select.push('ip_address');
    select = select.filter((i) => i !== 'ipv4_address');
    select = select.filter((i) => i !== 'ipv6_address');
  }
  if (select === undefined || select === null) select = Object.keys(hardwarePredicateMap);

  // retrieve required fields if not already on the list of fields to be selected
  if (!select.includes('id')) select.push('id');
  if (!select.includes('object_type')) select.push('object_type');

  // define related risks clause to restrict to only Risk since it available in other objects
  let relatedRiskClause = '', relatedRiskVariable = '';
  if (select.includes('related_risks')) {
    select = select.filter((i) => i !== 'related_risks');  
    relatedRiskVariable = '?related_risks';
    let predicate = hardwarePredicateMap['related_risks'].binding('?iri');
    relatedRiskClause = `
    OPTIONAL {
      ${predicate} .
      FILTER REGEX(str(?related_risks), "#Risk", "i")
    }`;
  }

  // build list of selection variables and predicates
  const { selectionClause, predicates } = buildSelectVariables(hardwarePredicateMap, select);

  return `
  SELECT ?iri ${selectionClause} ${relatedRiskVariable}
  FROM <tag:stardog:api:context:local>
  WHERE {
    BIND(${iri} AS ?iri)
    ?iri a <http://scap.nist.gov/ns/asset-identification#Hardware> .
    ${predicates}
    ${relatedRiskClause}
    {
      SELECT DISTINCT ?iri
      WHERE {
          ?inventory a <http://csrc.nist.gov/ns/oscal/common#AssetInventory> ;
              <http://csrc.nist.gov/ns/oscal/common#assets> ?iri .
      }
    }
  }
  `;
};
export const selectAllHardware = (select, args) => {
  if (select != null) {
    select = select.filter((i) => i !== 'ipv4_address');
    select = select.filter((i) => i !== 'ipv6_address');
    select.push('ip_address');
  }
  if (select === undefined || select === null) select = Object.keys(hardwarePredicateMap);

  // retrieve required fields if not already on the list of fields to be selected
  if (!select.includes('id')) select.push('id');
  if (!select.includes('object_type')) select.push('object_type');

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

  // define related risks clause to restrict to only Risk since it available in other objects
  let relatedRiskClause = '', relatedRiskVariable = '';
  if (select.includes('top_risk_severity') || select.includes('risk_count') || select.includes('related_risks')) {
    if (select.includes('related_risks')) select = select.filter((i) => i !== 'related_risks');    
    let predicate = hardwarePredicateMap['related_risks'].binding('?iri');
    relatedRiskVariable = '?related_risks';
    relatedRiskClause = `
    OPTIONAL {
      ${predicate} .
      FILTER REGEX(str(?related_risks), "#Risk", "i")
    }`;
  }

  // Build select clause and predicates
  const { selectionClause, predicates } = buildSelectVariables(hardwarePredicateMap, select);

  return `
  SELECT DISTINCT ?iri ${selectionClause} ${relatedRiskVariable}
  FROM <tag:stardog:api:context:local>
  WHERE {
    ?iri a <http://scap.nist.gov/ns/asset-identification#Hardware> . 
    ${predicates}
    ${relatedRiskClause}
    {
      SELECT DISTINCT ?iri
      WHERE {
          ?inventory a <http://csrc.nist.gov/ns/oscal/common#AssetInventory> ;
              <http://csrc.nist.gov/ns/oscal/common#assets> ?iri .
      }
    }
  }
  `;
};
export const deleteHardwareQuery = (id) => {
  const iri = `http://scap.nist.gov/ns/asset-identification#ComputingDevice-${id}`;
  return deleteHardwareByIriQuery(iri);
};
export const deleteHardwareByIriQuery = (iri) => {
  if (!iri.startsWith('<')) iri = `<${iri}>`;
  return `
  DELETE {
    GRAPH ${iri} {
      ?iri ?p ?o
    }
  } WHERE {
    GRAPH ${iri} {
      ?iri a <http://scap.nist.gov/ns/asset-identification#Hardware> .
      ?iri ?p ?o
    }
  }
  `;
};
export const attachToHardwareQuery = (id, field, itemIris) => {
  const iri = `<http://scap.nist.gov/ns/asset-identification#Hardware-${id}>`;
  if (!hardwarePredicateMap.hasOwnProperty(field)) return null;
  const { predicate } = hardwarePredicateMap[field];
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
export const detachFromHardwareQuery = (id, field, itemIris) => {
  const iri = `<http://scap.nist.gov/ns/asset-identification#Hardware-${id}>`;
  if (!hardwarePredicateMap.hasOwnProperty(field)) return null;
  const { predicate } = hardwarePredicateMap[field];
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
  `
}

// Predicate Maps
export const hardwarePredicateMap = {
  id: {
    predicate: "<http://darklight.ai/ns/common#id>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "id")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  object_type: {
    predicate: "<http://darklight.ai/ns/common#object_type>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "object_type");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  created: {
    predicate: "<http://darklight.ai/ns/common#created>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime`: null, this.predicate, "created");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  modified: {
    predicate: "<http://darklight.ai/ns/common#modified>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime`: null, this.predicate, "modified");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  labels: {
    predicate: "<http://darklight.ai/ns/common#labels>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "labels");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  label_name: {
    predicate: "<http://darklight.ai/ns/common#labels>/<http://darklight.ai/ns/common#name>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "label_name");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  notes: {
    predicate: "<http://darklight.ai/ns/common#notes>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "notes");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  external_references: {
    predicate: "<http://darklight.ai/ns/common#external_references>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "external_references");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  name: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#name>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, "name");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  description: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#description>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, "description");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  locations: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#locations>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, "locations");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  location_name: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#locations>/<http://darklight.ai/ns/common#name>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, "location_name");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  asset_id: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#asset_id>",
    binding: function (iri, value) { return  parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, "asset_id");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  asset_type: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#asset_type>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, "asset_type");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  asset_tag: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#asset_tag>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, "asset_tag");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  serial_number: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#serial_number>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, "serial_number");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  vendor_name: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#vendor_name>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, "vendor_name");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  version: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#version>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, "version");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  release_date: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#release_date>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime`: null, this.predicate, "release_date");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  implementation_point: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#implementation_point>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, "implementation_point");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  operational_status: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#operational_status>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, "operational_status");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  function: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#function>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, "function");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  cpe_identifier: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#cpe_identifier>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, "cpe_identifier");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  model: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#model>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, "model")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));}
  },
  motherboard_id: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#motherboard_id>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, "motherboard_id")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));}
  },
  installation_id: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#installation_id>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, "installation_id");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));}
  },
  installed_hardware: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#installed_hardware>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, "installed_hardware");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  installed_operating_system: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#installed_operating_system>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, "installed_operating_system");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  installed_os_name: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#installed_operating_system>/<http://scap.nist.gov/ns/asset-identification#name>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, "installed_os_name");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  is_publicly_accessible: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#is_publicly_accessible>",
    binding: function (iri, value) { return parameterizePredicate(iri, value !== undefined ? `"${value}"^^xsd:boolean` : null, this.predicate, "is_publicly_accessible");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));}
  },
  is_scanned: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#is_scanned>",
    binding: function (iri, value) { return parameterizePredicate(iri, value !== undefined ? `"${value}"^^xsd:boolean` : null, this.predicate, "is_scanned")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));}
  },
  is_virtual: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#is_virtual>",
    binding: function (iri, value) { return parameterizePredicate(iri, value !== undefined ? `"${value}"^^xsd:boolean` : null, this.predicate, "is_virtual")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));}
  },
  last_scanned: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#last_scanned>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime`: null, this.predicate, "last_scanned");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  bios_id: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#bios_id>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, "bios_id")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));}
  },
  fqdn: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#fqdn>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, "fqdn")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));}
  },
  hostname: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#hostname>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, "hostname")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));}
  },
  netbios_name: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#netbios_name>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, "netbios_name")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));}
  },
  network_id: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#network_id>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, "network_id")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));}
  },
  default_gateway: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#default_gateway>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, "default_gateway")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));}
  },
  vlan_id: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#vlan_id>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, "vlan_id")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));}
  },
  uri: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#uri>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:anyURI` : null, this.predicate, "uri")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));}
  },
  installed_software: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#installed_software>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, "installed_software");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  installed_software_name: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#installed_software>/<http://scap.nist.gov/ns/asset-identification#name>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, "installed_software_name");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  ip_address: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#ip_address>", // this should really be ipv4_address in ontology
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, "ip_address");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  ip_address_value: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#ip_address>/<http://scap.nist.gov/ns/asset-identification#ip_address_value>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, "ip_address_value");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  ipv4_address: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#ip_address>", // this should really be ipv4_address in ontology
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, "ip4_address");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  ipv6_address: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#ip_address>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, "ip6_address");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  mac_address: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#mac_address>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, "mac_address");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  mac_address_value: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#mac_address_value>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, "mac_address_value");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  ports: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#ports>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, "ports");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  connected_to_network: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#connected_to_network>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, "connected_to_network");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  baseline_configuration_name: {
    predicate: "<http://scap.nist.gov/ns/asset-identification#baseline_configuration_name>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, "baseline_configuration_name")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));}
  },
  related_risks: {
    predicate: "^<http://csrc.nist.gov/ns/oscal/assessment/common#subject_ref>/^<http://csrc.nist.gov/ns/oscal/assessment/common#subjects>/^<http://csrc.nist.gov/ns/oscal/assessment/common#related_observations>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, "related_risks");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  responsible_parties: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#responsible_parties>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "responsible_parties");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
};
