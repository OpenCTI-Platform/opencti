import { UserInputError } from 'apollo-server-express';
import {
  optionalizePredicate,
  parameterizePredicate,
  buildSelectVariables,
  generateId,
  OSCAL_NS,
} from '../../../utils.js';

// Utility functions
export function getReducer(type) {
  switch (type) {
    case 'COMPONENT':
      return componentReducer;
    default:
      throw new Error(`Unsupported reducer type ' ${type}'`);
  }
}

// Reducers
export const componentReducer = (item) => {
  // if no object type was returned, compute the type from the IRI
  if (item.object_type === undefined) {
    item.object_type = 'component';
  }
  // TODO: WORKAROUND missing component type
  if (item.component_type === undefined) {
    switch (item.asset_type) {
      case 'software':
      case 'operating-system':
      case 'application-software':
        item.component_type = 'software';
        break;
      case 'network':
        item.component_type = 'network';
        break;
      default:
        console.error(
          `[CYIO] UNKNOWN-COMPONENT Unknown component type '${item.component_type}' for object ${item.iri}`
        );
        console.error(`[CYIO] UNKNOWN-TYPE Unknown asset type '${item.asset_type}' for object ${item.iri}`);
        if (item.iri.includes('Software')) item.component_type = 'software';
        if (item.iri.includes('Network')) item.component_type = 'network';
        if (item.component_type === undefined) return null;
    }
  }
  // END WORKAROUND

  return {
    id: item.id,
    standard_id: item.id,
    entity_type: 'component',
    ...(item.iri && { parent_iri: item.iri }),
    ...(item.object_type && { object_type: item.object_type }),
    ...(item.created && { created: item.created }),
    ...(item.modified && { modified: item.modified }),
    ...(item.labels && { labels_iri: item.labels }),
    ...(item.links && { links_iri: item.links }),
    ...(item.remarks && { remarks_iri: item.remarks }),
    ...(item.name && { name: item.name }),
    ...(item.description && { description: item.description }),
    // component
    ...(item.component_type && { component_type: item.component_type }),
    ...(item.purpose && { purpose: item.purpose }),
    ...(item.inherited_uuid && { inherited_uuid: item.inherited_uuid }),
    ...(item.leveraged_authorization_uuid && { leveraged_authorization_uuid: item.leveraged_authorization_uuid }),
    ...(item.protocols && { protocols_iri: item.protocols }),
    ...(item.control_implementations && { control_implementations_iri: item.control_implementations }),
    ...(item.responsible_roles && { responsible_roles_iri: item.responsible_roles }),
    ...(item.props && { props: item.props }),
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
    // Software - OperatingSystem - ApplicationSoftware
    ...(item.function && { function: item.function }),
    ...(item.cpe_identifier && { cpe_identifier: item.cpe_identifier }),
    ...(item.software_identifier && { software_identifier: item.software_identifier }),
    ...(item.patch_level && { patch_level: item.patch_level }),
    ...(item.installation_id && { installation_id: item.installation_id }),
    ...(item.license_key && { license_key: item.license_key }),
    // Service
    ...(item.provided_by && { provided_by: item.provided_by }),
    ...(item.used_by && { used_by: item.used_by }),
    // Interconnection - Network
    ...(item.isa_title && { isa_title: item.isa_title }),
    ...(item.isa_date && { isa_date: item.isa_date }),
    ...(item.isa_remote_system_name && { isa_remote_system_name: item.isa_remote_system_name }),
  };
};

// Component Resolver Support functions
export const insertComponentQuery = (propValues) => {
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

  const iri = `<http://csrc.nist.gov/ns/oscal/common#Component-${id}>`;
  const insertPredicates = Object.entries(propValues)
    .filter((propPair) => componentPredicateMap.hasOwnProperty(propPair[0]))
    .map((propPair) => componentPredicateMap[propPair[0]].binding(iri, propPair[1]))
    .join('. \n      ');
  const query = `
  INSERT DATA {
    GRAPH ${iri} {
      ${iri} a <http://csrc.nist.gov/ns/oscal/common#Component> .
      ${iri} a <http://csrc.nist.gov/ns/oscal/common#Object> .
      ${iri} a <http://darklight.ai/ns/common#Object> .
      ${iri} <http://darklight.ai/ns/common#id> "${id}" .
      ${iri} <http://darklight.ai/ns/common#object_type> "component" . 
      ${iri} <http://darklight.ai/ns/common#created> "${timestamp}"^^xsd:dateTime . 
      ${iri} <http://darklight.ai/ns/common#modified> "${timestamp}"^^xsd:dateTime . 
      ${insertPredicates}
    }
  }
  `;
  return { iri, id, query };
};
export const selectComponentQuery = (id, select) => {
  return selectComponentByIriQuery(`http://csrc.nist.gov/ns/oscal/common#Component-${id}`, select);
};
export const selectComponentByIriQuery = (iri, select) => {
  if (!iri.startsWith('<')) iri = `<${iri}>`;
  if (select === undefined || select === null) select = Object.keys(componentPredicateMap);
  if (!select.includes('component_type')) select.push('component_type');
  if (!select.includes('asset_type')) select.push('asset_type');

  const { selectionClause, predicates } = buildSelectVariables(componentPredicateMap, select);
  return `
  SELECT ${selectionClause}
  FROM <tag:stardog:api:context:local>
  WHERE {
    BIND(${iri} AS ?iri)
    ?iri a <http://csrc.nist.gov/ns/oscal/common#Component> .
    ${predicates}
  }
  `;
};
export const selectAllComponents = (select, args, parent) => {
  let constraintClause = '';
  if (select === undefined || select === null) select = Object.keys(componentPredicateMap);
  if (select.includes('props')) select = Object.keys(componentPredicateMap);
  if (!select.includes('id')) select.push('id');
  if (!select.includes('component_type')) select.push('component_type');
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

  const { selectionClause, predicates } = buildSelectVariables(componentPredicateMap, select);
  // add constraint clause to limit to those that are referenced by the specified POAM
  if (parent !== undefined && parent.iri !== undefined) {
    let classTypeIri;
    let predicate;
    if (parent.entity_type === 'assessment-asset') {
      classTypeIri = '<http://csrc.nist.gov/ns/oscal/assessment/common#AssessmentAsset>';
      predicate = '<http://csrc.nist.gov/ns/oscal/assessment/common#components>';
    }
    // define a constraint to limit retrieval to only those referenced by the parent
    constraintClause = `
    {
      SELECT DISTINCT ?iri
      WHERE {
          <${parent.iri}> a ${classTypeIri} ;
            ${predicate} ?iri .
      }
    }
    `;
  } else {
    constraintClause = `
    {
      SELECT DISTINCT ?iri
      WHERE {
          ?inventory a <http://csrc.nist.gov/ns/oscal/common#AssetInventory> ;
                <http://csrc.nist.gov/ns/oscal/common#assets> ?iri .
      }
    }
    `;
  }

  return `
  SELECT DISTINCT ?iri ${selectionClause} 
  FROM <tag:stardog:api:context:local>
  WHERE {
    ?iri a <http://csrc.nist.gov/ns/oscal/common#Component> . 
    ${predicates}
    ${constraintClause}
  }
  `;
};
export const deleteComponentQuery = (id) => {
  const iri = `http://csrc.nist.gov/ns/oscal/common#Component-${id}`;
  return deleteComponentByIriQuery(iri);
};
export const deleteComponentByIriQuery = (iri) => {
  return `
  DELETE {
    GRAPH <${iri}> {
      ?iri ?p ?o
    }
  } WHERE {
    GRAPH <${iri}> {
      ?iri a <http://csrc.nist.gov/ns/oscal/common#Component> .
      ?iri ?p ?o
    }
  }
  `;
};
export const attachToComponentQuery = (id, field, itemIris) => {
  const iri = `<http://csrc.nist.gov/ns/oscal/common#Component-${id}>`;
  if (!activityPredicateMap.hasOwnProperty(field)) return null;
  const { predicate } = activityPredicateMap[field];
  let statements;
  if (Array.isArray(itemIris)) {
    statements = itemIris.map((itemIri) => `${iri} ${predicate} ${itemIri}`).join('.\n        ');
  } else {
    if (!itemIris.startsWith('<')) itemIris = `<${itemIris}>`;
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
export const detachFromComponentQuery = (id, field, itemIris) => {
  const iri = `<http://csrc.nist.gov/ns/oscal/common#Component-${id}>`;
  if (!componentPredicateMap.hasOwnProperty(field)) return null;
  const { predicate } = componentPredicateMap[field];
  let statements;
  if (Array.isArray(itemIris)) {
    statements = itemIris.map((itemIri) => `${iri} ${predicate} ${itemIri}`).join('.\n        ');
  } else {
    if (!itemIris.startsWith('<')) itemIris = `<${itemIris}>`;
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
export const componentPredicateMap = {
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
  component_type: {
    predicate: '<http://csrc.nist.gov/ns/oscal/common#component_type>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'component_type');
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
  purpose: {
    predicate: '<http://csrc.nist.gov/ns/oscal/common#purpose>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'purpose');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  responsible_roles: {
    predicate: '<http://csrc.nist.gov/ns/oscal/common#responsible_roles>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'responsible_roles');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  inherited_uuid: {
    predicate: '<http://csrc.nist.gov/ns/oscal/common#inherited_uuid>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'inherited_uuid');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  leveraged_authorization_uuid: {
    predicate: '<http://csrc.nist.gov/ns/oscal/common#leveraged_authorization_uuid>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'leveraged_authorization');
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
  baseline_configuration_name: {
    predicate: '<http://scap.nist.gov/ns/asset-identification#baseline_configuration_name>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'baseline_configuration_name');
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
  installation_id: {
    predicate: '<http://scap.nist.gov/ns/asset-identification#installation_id>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'installation_id');
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
  model: {
    predicate: '<http://scap.nist.gov/ns/asset-identification#model>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'model');
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
  vlan_id: {
    predicate: '<http://scap.nist.gov/ns/asset-identification#vlan_id>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'vlan_id');
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
  validation_type: {
    predicate: '<http://darklight.ai/ns/nist-7693-dlex#validation_type>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'validation_type');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  validation_reference: {
    predicate: '<http://darklight.ai/ns/nist-7693-dlex#validation_reference>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'validation_reference');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
};

// Function to convert an Asset to a Component
export function convertAssetToComponent(asset) {
  const propList = [];

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
      case 'component_type':
      case 'name':
      case 'description':
      case 'purpose':
      case 'operational_status':
      case 'links':
      case 'responsible_roles':
      case 'protocols':
        continue;
      case 'created':
      case 'modified':
      case 'last_scanned':
        if (value instanceof Date) value = value.toISOString();
        break;
      case 'cpe_identifier':
        key = 'software-identifier';
        break;
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
    entity_type: 'component',
    ...(asset.iri && { iri: asset.iri }),
    ...(asset.created && { created: asset.created }),
    ...(asset.modified && { modified: asset.modified }),
    ...(asset.component_type && { component_type: asset.component_type }),
    ...(asset.name && { name: asset.name }),
    ...(asset.description && { description: asset.description }),
    ...(asset.purpose && { purpose: asset.purpose }),
    props: propList,
    ...(asset.operational_status && { operational_status: asset.operational_status }),
    ...(asset.links && { links_iri: asset.links }),
    ...(asset.responsible_roles && { responsible_roles_iri: asset.responsible_roles }),
    ...(asset.protocols && { protocols_iri: asset.protocols }),
    ...(asset.remarks && { remarks_iri: asset.remarks }),
  };
}
