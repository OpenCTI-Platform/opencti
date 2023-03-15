import { UserInputError } from 'apollo-server-errors';
import { 
    optionalizePredicate, 
    parameterizePredicate, 
    buildSelectVariables, 
    attachQuery,
    detachQuery,
    generateId, 
    DARKLIGHT_NS,
  } from '../../../utils.js';
    
    // Reducer Selection
  export function getReducer(type) {
    switch (type) {
      case 'SYSTEM-CONFIGURATION':
        return systemConfigurationReducer;
      default:
        throw new UserInputError(`Unsupported reducer type ' ${type}'`)
    }
  }
    
//
// Reducers
//
const systemConfigurationReducer = (item) => {
  // if no object type was returned, compute the type from the IRI
  if (item.object_type === undefined) {
    if (item.entity_type !== undefined) item.object_type = item.entity_type;
    if (item.iri.includes('system-configuration')) item.object_type = 'system-configuration';
  }

  return {
    iri: item.iri,
    id: item.id,
    ...(item.object_type && { entity_type: item.object_type }),
    ...(item.created && { created: item.created }),
    ...(item.modified && { modified: item.modified }),
    ...(item.name && { name: item.name }),
    ...(item.description && { description: item.description }),
    ...(item.version && { version: item.version }),
    ...(item.dashboard_wizard_config && { dashboard_wizard_config: item.dashboard_wizard_config }),
    // hints for field-level resolver queries
    ...(item.settings && { settings_iri: item.settings }),
    ...(item.data_markings && { data_markings_iri: item.data_markings }),
    ...(item.data_sources && { data_sources_iri: item.data_sources }),
    ...(item.information_type_catalogs && { information_type_catalogs_iri: item.information_type_catalogs }),
    ...(item.organizations && { organizations_iri: item.organizations }),
    ...(item.themes && { themes_iri: item.themes }),
    ...(item.workspaces && { workspaces_iri: item.workspaces }),
  }
};

// Query Builders

export const attachToSystemConfigurationQuery = (id, field, itemIris) => {
  if (!systemConfigurationPredicateMap.hasOwnProperty(field)) return null;
  const iri = `<http://cyio.darklight.ai/system-configuration--${id}>`;
  const predicate = systemConfigurationPredicateMap[field].predicate;

  let statements;
  if (Array.isArray(itemIris)) {
    statements = itemIris
      .map((itemIri) => `${iri} ${predicate} ${itemIri}`)
      .join(".\n        ")
    }
  else {
    if (!itemIris.startsWith('<')) itemIris = `<${itemIris}>`;
    statements = `${iri} ${predicate} ${itemIris} .`;
  }

  return attachQuery(
    iri, 
    statements, 
    systemConfigurationPredicateMap, 
    '<http://darklight.ai/ns/cyio/system-configuration#SystemConfiguraiton>'
  );
}

export const detachFromSystemConfigurationQuery = (id, field, itemIris) => {
  if (!systemConfigurationPredicateMap.hasOwnProperty(field)) return null;
  const iri = `<http://cyio.darklight.ai/system-configuration--${id}>`;
  const predicate = systemConfigurationPredicateMap[field].predicate;

  let statements;
  if (Array.isArray(itemIris)) {
    statements = itemIris
      .map((itemIri) => `${iri} ${predicate} ${itemIri}`)
      .join(".\n        ")
    }
  else {
    if (!itemIris.startsWith('<')) itemIris = `<${itemIris}>`;
    statements = `${iri} ${predicate} ${itemIris} .`;
  }

  return detachQuery(
    iri, 
    statements, 
    systemConfigurationPredicateMap, 
    '<http://darklight.ai/ns/cyio/system-configuration#SystemConfiguraiton>'
  );
}


 
// Predicate Maps
export const systemConfigurationPredicateMap = {
  id: {
    predicate: "<http://darklight.ai/ns/common#id>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "id");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  object_type: {
    predicate: "<http://darklight.ai/ns/common#object_type>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "object_type");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  entity_type: {
    predicate: "<http://darklight.ai/ns/common#object_type>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "entity_type");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  created: {
    predicate: "<http://darklight.ai/ns/common#created>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime` : null,  this.predicate, "created");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  modified: {
    predicate: "<http://darklight.ai/ns/common#modified>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime` : null,  this.predicate, "modified");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  name: {
    predicate: "<http://darklight.ai/ns/cyio#name>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "name");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  description: {
    predicate: "<http://darklight.ai/ns/cyio#description>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"@en-US` : null,  this.predicate, "description");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  version: {
    predicate: "<http://darklight.ai/ns/cyio#version>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "version");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  settings: {
    predicate: "<http://darklight.ai/ns/cyio/system-configuration#settings>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "settings");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  data_markings: {
    predicate: "<http://darklight.ai/ns/cyio/system-configuration#data_markings>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "data_markings");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  data_sources: {
    predicate: "<http://darklight.ai/ns/cyio/system-configuration#data_sources>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "data_sources");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  information_type_catalogs: {
    predicate: "<http://darklight.ai/ns/cyio/system-configuration#information_type_catalogs>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "information_type_catalogs");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  organizations: {
    predicate: "<http://darklight.ai/ns/cyio/system-configuration#organizations>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "organizations");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  themes: {
    predicate: "<http://darklight.ai/ns/cyio/system-configuration#themes>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "themes");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  workspaces: {
    predicate: "<http://darklight.ai/ns/cyio/system-configuration#workspaces>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "workspaces");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  dashboard_wizard_config: {
    predicate: "<http://darklight.ai/ns/cyio/system-configuration#dashboard_wizard_config>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:base64Binary` : null,  this.predicate, "dashboard_wizard_config");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
};

// Serialization schema
export const singularizeSystemConfigurationSchema = { 
  singularizeVariables: {
    "": false, // so there is an object as the root instead of an array
    "id": true,
    "iri": true,
    "object_type": true,
    "entity_type": true,
    "created": true,
    "modified": true,
    "name": true,
    "description": true,
    "version": true,
    "dashboard_wizard_config": true,
  }
};
