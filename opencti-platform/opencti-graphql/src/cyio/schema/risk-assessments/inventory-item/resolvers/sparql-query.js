import { UserInputError } from 'apollo-server-errors';
import {
  optionalizePredicate,
  parameterizePredicate,
  buildSelectVariables,
  attachQuery,
  detachQuery,
  generateId,
  OSCAL_NS,
} from '../../../utils.js';
import { selectOscalTaskByIriQuery } from '../../assessment-common/resolvers/sparql-query.js';

// Utility functions
export function getReducer(type) {
  switch (type) {
    case 'INVENTORY-ITEM':
      return inventoryItemReducer;
    default:
      throw new UserInputError(`Unsupported reducer type ' ${type}'`);
  }
}

// Reducers
export const inventoryItemReducer = (item) => {
  // if no object type was returned, compute the type from the IRI
  if (item.object_type === undefined) {
    item.object_type = 'inventory-item';
  }

  return {
    id: item.id,
    standard_id: item.id,
    entity_type: 'inventory-item',
    ...(item.iri && { parent_iri: item.iri }),
    ...(item.created && { created: item.created }),
    ...(item.modified && { modified: item.modified }),
    ...(item.labels && { labels_iri: item.labels }),
    ...(item.links && { links_iri: item.links }),
    ...(item.remarks && { remarks_iri: item.remarks }),
    ...(item.name && { name: item.name }),
    ...(item.description && { description: item.description }),
    // inventory-item
    ...(item.responsible_parties && { responsible_party_iris: item.responsible_parties }),
    ...(item.implemented_components && { implemented_component_iris: item.implemented_components }),
    // Asset
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
    ...(item.locations && { locations_iri: item.locations }),
    ...(item.allows_authenticated_scan !== undefined && { allows_authenticated_scan: item.allows_authenticated_scan }),
    ...(item.is_publicly_accessible !== undefined && { is_publicly_accessible: item.is_publicly_accessible }),
    ...(item.is_scanned !== undefined && { is_scanned: item.is_scanned }),
    ...(item.last_scanned && { last_scanned: item.last_scanned }),
    // Hardware
    ...(item.function && { function: item.function }),
    ...(item.cpe_identifier && { cpe_identifier: item.cpe_identifier }),
    ...(item.installation_id && { installation_id: item.installation_id }),
    ...(item.model && { model: item.model }),
    // ...(item.motherboard_id && {motherboard_id: item.motherboard_id}),
    ...(item.baseline_configuration_name && { baseline_configuration_name: item.baseline_configuration_name }),
    ...(item.is_virtual !== undefined && { is_virtual: item.is_virtual }),
    ...(item.ip_address && { ip_addr_iri: item.ip_address }),
    ...(item.mac_address && { mac_addr_iri: item.mac_address }),
    // ComputingDevice
    // ...(item.bios_id && {bios_id: item.bios_id}),
    ...(item.network_id && { network_id: item.network_id }),
    ...(item.vlan_id && { vlan_id: item.vlan_id }),
    ...(item.default_gateway && { default_gateway: item.default_gateway }),
    ...(item.fqdn && { fqdn: item.fqdn }),
    ...(item.hostname && { hostname: item.hostname }),
    ...(item.netbios_name && { netbios_name: item.netbios_name }),
    ...(item.uri && { uri: item.uri }),
    // DarkLight
    ...(item.installed_hardware && { installed_hw_iri: item.installed_hardware }),
    ...(item.installed_operating_system && { installed_os_iri: item.installed_operating_system }),
    ...(item.installed_software && { installed_sw_iri: item.installed_software }),
    ...(item.ports && { ports_iri: item.ports }),
    ...(item.connected_to_network && { conn_network_iri: item.connected_to_network }),
  };
};

// InventoryItem resolver support functions
export const insertInventoryItemQuery = (propValues) => {
  const id_material = {
    ...(propValues.name && { name: propValues.name }),
    ...(propValues.methods && { methods: propValues.methods }),
  };
  const id = generateId(id_material, OSCAL_NS);
  const timestamp = new Date().toISOString();

  // escape any special characters (e.g., newline)
  if (propValues.description !== undefined) {
    if (propValues.description.includes('\n')) propValues.description = propValues.description.replace(/\n/g, '\\n');
    if (propValues.description.includes('"')) propValues.description = propValues.description.replace(/\"/g, '\\"');
    if (propValues.description.includes("'")) propValues.description = propValues.description.replace(/\'/g, "\\'");
  }

  const iri = `<http://csrc.nist.gov/ns/oscal/common#InventoryItem-${id}>`;
  const insertPredicates = Object.entries(propValues)
    .filter((propPair) => inventoryItemPredicateMap.hasOwnProperty(propPair[0]))
    .map((propPair) => inventoryItemPredicateMap[propPair[0]].binding(iri, propPair[1]))
    .join('. \n      ');
  const query = `
  INSERT DATA {
    GRAPH ${iri} {
      ${iri} a <http://csrc.nist.gov/ns/oscal/common#InventoryItem> .
      ${iri} a <http://csrc.nist.gov/ns/oscal/common#Object> .
      ${iri} a <http://darklight.ai/ns/common#Object> .
      ${iri} <http://darklight.ai/ns/common#id> "${id}" .
      ${iri} <http://darklight.ai/ns/common#object_type> "inventory-item" . 
      ${iri} <http://darklight.ai/ns/common#created> "${timestamp}"^^xsd:dateTime . 
      ${iri} <http://darklight.ai/ns/common#modified> "${timestamp}"^^xsd:dateTime . 
      ${insertPredicates}
    }
  }
  `;
  return { iri, id, query };
};
export const selectInventoryItemQuery = (id, select) => {
  return selectInventoryItemByIriQuery(`http://csrc.nist.gov/ns/oscal/common#InventoryItem-${id}`, select);
};
export const selectInventoryItemByIriQuery = (iri, select) => {
  if (!iri.startsWith('<')) iri = `<${iri}>`;
  if (select === undefined || select === null) select = Object.keys(inventoryItemPredicateMap);
  const { selectionClause, predicates } = buildSelectVariables(inventoryItemPredicateMap, select);
  return `
  SELECT ?iri ${selectionClause}
  FROM <tag:stardog:api:context:local>
  WHERE {
    BIND(${iri} AS ?iri)
    ?iri a <http://csrc.nist.gov/ns/oscal/common#InventoryItem> .
    ${predicates}
  }
  `;
};
export const selectAllInventoryItems = (select, args) => {
  if (select === undefined || select === null) select = Object.keys(inventoryItemPredicateMap);
  if (select.includes('props')) {
    select = Object.keys(inventoryItemPredicateMap);
    if (select.includes('label_name')) select = select.filter((i) => i !== 'label_name');
    if (select.includes('locations')) select = select.filter((i) => i !== 'locations');
    if (select.includes('installed_operating_system'))
      select = select.filter((i) => i !== 'installed_operating_system');
    if (select.includes('installed_software')) select = select.filter((i) => i !== 'installed_software');
    if (select.includes('ip_address')) select = select.filter((i) => i !== 'ip_address');
    if (select.includes('mac_address')) select = select.filter((i) => i !== 'mac_address');
    // if (select.includes('implemented_components')) delete select.implemented_components;
  }
  if (!select.includes('id')) select.push('id');
  if (!select.includes('asset_type')) select.push('asset_type');

  if (args !== undefined) {
    // add value of filter's key to cause special predicates to be included
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

  const { selectionClause, predicates } = buildSelectVariables(inventoryItemPredicateMap, select);
  return `
  SELECT DISTINCT ?iri ${selectionClause} 
  FROM <tag:stardog:api:context:local>
  WHERE {
    ?iri a <http://csrc.nist.gov/ns/oscal/common#InventoryItem> . 
    ${predicates}
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
export const deleteInventoryItemQuery = (id) => {
  const iri = `http://csrc.nist.gov/ns/oscal/common#InventoryItem-${id}`;
  return deleteInventoryItemByIriQuery(iri);
};
export const deleteInventoryItemByIriQuery = (iri) => {
  return `
  DELETE {
    GRAPH <${iri}> {
      ?iri ?p ?o
    }
  } WHERE {
    GRAPH <${iri}> {
      ?iri a <http://csrc.nist.gov/ns/oscal/common#InventoryItem> .
      ?iri ?p ?o
    }
  }
  `;
};
export const attachToInventoryItemQuery = (id, field, itemIris) => {
  if (!inventoryItemPredicateMap.hasOwnProperty(field)) return null;
  const iri = `<http://csrc.nist.gov/ns/oscal/common#InventorItem-${id}>`;
  const { predicate } = inventoryItemPredicateMap[field];

  let statements;
  if (Array.isArray(itemIris)) {
    statements = itemIris.map((itemIri) => `${iri} ${predicate} ${itemIri}`).join('.\n        ');
  } else {
    if (!itemIris.startsWith('<')) itemIris = `<${itemIris}>`;
    statements = `${iri} ${predicate} ${itemIris} .`;
  }

  return attachQuery(
    iri, 
    statements, 
    inventoryItemPredicateMap, 
    '<http://csrc.nist.gov/ns/oscal/common#InventoryItem>'
  );
};
export const detachFromInventoryItemQuery = (id, field, itemIris) => {
  if (!inventoryItemPredicateMap.hasOwnProperty(field)) return null;
  const iri = `<http://csrc.nist.gov/ns/oscal/assessment/common#InventoryItem-${id}>`;
  const { predicate } = inventoryItemPredicateMap[field];

  let statements;
  if (Array.isArray(itemIris)) {
    statements = itemIris.map((itemIri) => `${iri} ${predicate} ${itemIri}`).join('.\n        ');
  } else {
    if (!itemIris.startsWith('<')) itemIris = `<${itemIris}>`;
    statements = `${iri} ${predicate} ${itemIris} .`;
  }

  return detachQuery(
    iri, 
    statements, 
    inventoryItemPredicateMap, 
    '<http://csrc.nist.gov/ns/oscal/common#InventoryItem>'
  );
};

// Predicate Maps
export const inventoryItemPredicateMap = {
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
  links: {
    predicate: '<http://csrc.nist.gov/ns/oscal/common#links>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'links');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  remarks: {
    predicate: '<http://csrc.nist.gov/ns/oscal/common#remarks>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'remarks');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  responsible_parties: {
    predicate: '<http://csrc.nist.gov/ns/oscal/common#responsible_parties>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'responsible_parties');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  implemented_components: {
    predicate: '<http://csrc.nist.gov/ns/oscal/common#implemented_components>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'implemented_components');
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
  allows_authenticated_scan: {
    predicate: '<http://csrc.nist.gov/ns/oscal/common#allows_authenticted_scan>',
    binding(iri, value) {
      return parameterizePredicate(
        iri,
        value !== undefined ? `"${value}"^^xsd:boolean` : null,
        this.predicate,
        'allows_authenticated_scan'
      );
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
  // release_date: {
  //   predicate: "<http://scap.nist.gov/ns/asset-identification#release_date>",
  //   binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime`: null, this.predicate, "release_date");},
  //   optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  // },
  // implementation_point: {
  //   predicate: "<http://scap.nist.gov/ns/asset-identification#implementation_point>",
  //   binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, "implementation_point");},
  //   optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  // },
  // operational_status: {
  //   predicate: "<http://scap.nist.gov/ns/asset-identification#operational_status>",
  //   binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, "operational_status");},
  //   optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  // },
  function: {
    predicate: '<http://scap.nist.gov/ns/asset-identification#function>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'function');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  // cpe_identifier: {
  //   predicate: "<http://scap.nist.gov/ns/asset-identification#cpe_identifier>",
  //   binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, "cpe_identifier");},
  //   optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  // },
  model: {
    predicate: '<http://scap.nist.gov/ns/asset-identification#model>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'model');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  // motherboard_id: {
  //   predicate: "<http://scap.nist.gov/ns/asset-identification#motherboard_id>",
  //   binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, "motherboard_id")},
  //   optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));}
  // },
  // installation_id: {
  //   predicate: "<http://scap.nist.gov/ns/asset-identification#installation_id>",
  //   binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, "installation_id");},
  //   optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));}
  // },
  // installed_hardware: {
  //   predicate: "<http://scap.nist.gov/ns/asset-identification#installed_hardware>",
  //   binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, "installed_hardware");},
  //   optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  // },
  installed_operating_system: {
    predicate: '<http://scap.nist.gov/ns/asset-identification#installed_operating_system>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'installed_operating_system');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  installed_os_id: {
    predicate:
      '<http://scap.nist.gov/ns/asset-identification#installed_operating_system>/<http://darklight.ai/ns/common#id>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'installed_os_id');
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
  // bios_id: {
  //   predicate: "<http://scap.nist.gov/ns/asset-identification#bios_id>",
  //   binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, "bios_id")},
  //   optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));}
  // },
  fqdn: {
    predicate: '<http://scap.nist.gov/ns/asset-identification#fqdn>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'fqdn');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  // hostname: {
  //   predicate: "<http://scap.nist.gov/ns/asset-identification#hostname>",
  //   binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, "hostname")},
  //   optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));}
  // },
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
  // default_gateway: {
  //   predicate: "<http://scap.nist.gov/ns/asset-identification#default_gateway>",
  //   binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, "default_gateway")},
  //   optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));}
  // },
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
  installed_software_id: {
    predicate: '<http://scap.nist.gov/ns/asset-identification#installed_software>/<http://darklight.ai/ns/common#id>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'installed_software_id');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  installed_software_name: {
    predicate:
      '<http://scap.nist.gov/ns/asset-identification#installed_software>/<http://scap.nist.gov/ns/asset-identification#name>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'installed_software_name');
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
  ip_address_value: {
    predicate:
      '<http://scap.nist.gov/ns/asset-identification#ip_address>/<http://scap.nist.gov/ns/asset-identification#ip_address_value>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'ip_address_value');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  // ipv4_address: {
  //   predicate: "<http://scap.nist.gov/ns/asset-identification#ip_address>", // this should really be ipv4_address in ontology
  //   binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, "ip4_address");},
  //   optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  // },
  // ipv6_address: {
  //   predicate: "<http://scap.nist.gov/ns/asset-identification#ip_address>",
  //   binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, "ip6_address");},
  //   optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  // },
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
    predicate:
      '<http://scap.nist.gov/ns/asset-identification#mac_address>/<http://scap.nist.gov/ns/asset-identification#mac_address_value>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'mac_address_value');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  // ports: {
  //   predicate: "<http://scap.nist.gov/ns/asset-identification#ports>",
  //   binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, "ports");},
  //   optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  // },
  // connected_to_network: {
  //   predicate: "<http://scap.nist.gov/ns/asset-identification#connected_to_network>",
  //   binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, "connected_to_network");},
  //   optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  // },
  baseline_configuration_name: {
    predicate: '<http://scap.nist.gov/ns/asset-identification#baseline_configuration_name>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'baseline_configuration_name');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
};

// Function to convert an Asset to a Component
export function convertAssetToInventoryItem(asset) {
  const propList = [];
  const implementedComponents = [];

  // Convert the each key/value pair of asset into an individual OSCAL Property objects
  for (let [key, value] of Object.entries(asset)) {
    const namespace = 'http://csrc.nist.gov/ns/oscal';
    switch (key) {
      case 'iri':
      case 'id':
      case 'object_type':
      case 'entity_type':
      case 'standard_id':
      case 'links':
      case 'labels':
      case 'remarks':
      case 'name':
      case 'description':
      case 'responsible_parties':
      case 'implemented_components':
      case 'connected_to_network':
        // case 'installed_os_id':
        // case 'installed_software_id':
        continue;
      case 'created':
      case 'modified':
      case 'last_scanned':
        if (value instanceof Date) value = value.toISOString();
        break;
      case 'is_scanned':
      case 'allows_authenticated_scans':
        value = value === true ? 'yes' : 'no';
        break;
      case 'is_publicly_accessible':
        key = 'public';
        value = value === true ? 'yes' : 'no';
        break;
      case 'is_virtual':
        key = 'virtual';
        value = value === true ? 'yes' : 'no';
        break;
      // case 'ip_address':
      case 'ip_address_value':
        key = asset.ip_address_value.includes(':') ? 'ipv6-address' : 'ipv4-address';
        value = asset.ip_address_value;
        break;
      // case 'installed_operating_system':
      case 'installed_os_name':
        key = 'os-name';
        value = asset.installed_os_name;
        break;
      case 'installed_os_id':
        const implementedComponent = {
          id: generateId(),
          entity_type: 'implemented-component',
          component_uuid: asset.installed_os_id[0],
        };
        implementedComponents.push(implementedComponent);
        continue;
      case 'mac_address_value':
        key = 'mac-address';
        if (!asset.mac_address_value.includes(':')) {
          value = asset.mac_address_value.replace(/([A-F0-9]{2})(?=[A-F0-9])/g, '$1:');
        } else {
          value = asset.mac_address_value;
        }
        break;
      case 'installed_software_name':
        if ('installed_software_name' in asset) {
          key = 'software-name';
          value = asset.installed_software_name;
        }
        break;
      case 'installed_software_id':
        // TODO: Should this be actually represented as 'implemented_components'?
        //       Why not have the name, version, asset_type as a prop
        for (const swId of asset.installed_software_id) {
          const implementedComponent = {
            id: generateId(),
            entity_type: 'implemented-component',
            component_uuid: swId,
          };
          implementedComponents.push(implementedComponent);
        }
        continue;
      case 'location_name':
        key = 'physical-location';
        value = asset.location_name;
        break;
      case 'ports':
        continue;
      default:
        break;
    }

    if (value === null || value === 'null') continue;
    // replace '_' with'-'
    if (key.includes('_')) key = key.replace(/_/g, '-');
    // generate id based on the name and the namespace
    const id_material = {
      name: `${key}`,
      ns: `${namespace}`,
      value: Array.isArray(value) ? value.toString() : `${value}`,
    };
    const id = generateId(id_material, OSCAL_NS);
    const prop = {
      id: `${id}`,
      entity_type: 'property',
      prop_name: `${key}`,
      ns: `${namespace}`,
      value: Array.isArray(value) ? value.toString() : `${value}`,
      // class: `${},
    };
    propList.push(prop);
  }

  return {
    id: asset.id,
    entity_type: 'inventory-item',
    ...(asset.iri && { iri: asset.iri }),
    ...(asset.id && { id: asset.id }),
    ...(asset.created && { created: asset.created }),
    ...(asset.modified && { modified: asset.modified }),
    ...(asset.name && { name: asset.name }),
    ...(asset.description && { description: asset.description }),
    props: propList,
    ...(asset.links && { links_iri: asset.links }),
    ...(asset.responsible_parties && { responsible_party_iris: asset.responsible_parties }),
    ...(implementedComponents.length > 0 && { implemented_components: implementedComponents }),
    ...(asset.implemented_components && { implemented_component_iris: asset.implemented_components }),
    ...(asset.remarks && { remarks_iri: asset.remarks }),
  };
}
