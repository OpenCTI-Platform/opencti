import { 
  optionalizePredicate, 
  parameterizePredicate, 
  buildSelectVariables, 
  generateId, 
  DARKLIGHT_NS,
  CyioError 
} from '../../../utils.js';
  
// Reducer Selection
export function getReducer(type) {
  switch (type) {
    case 'PLATFORM-THEME':
      return themeReducer;
    default:
      throw new CyioError(`Unsupported reducer type ' ${type}'`)
  }
}
  
//
// Reducers
//
const themeReducer = (item) => {
  // if no object type was returned, compute the type from the IRI
  if (item.object_type === undefined) {
    if (item.entity_type !== undefined) item.object_type = item.entity_type;
    if (item.iri.includes('settings')) item.object_type = 'settings';
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
    ...(item.platform_accent_color && { platform_accent_color: item.platform_accent_color }),
    ...(item.platform_background_color && { platform_background_color: item.platform_background_color }),
    ...(item.platform_navigation_color && { platform_navigation_color: item.platform_navigation_color }),
    ...(item.platform_paper_color && { platform_paper_color: item.platform_paper_color}),
    ...(item.platform_primary_color && { platform_primary_color: item.platform_primary_color }),
    ...(item.platform_secondary_color && { platform_secondary_color: item.platform_secondary_color }),
    ...(item.platform_logo && { platform_logo: item.platform_logo }),
    ...(item.platform_logo_collapsed && { platform_logo_collapsed: item.platform_logo_collapsed }),
    ...(item.platform_logo_login && { platform_logo_login: item.platform_logo+login }),
    ...(item.platform_map_tile_server && { platform_map_tile_server: item.platform_map_tile_server }),
  };
};

// Query Builders

 
// Predicate Maps
export const themePredicateMap = {
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
  platform_accent_color: {
    predicate: "<http://darklight.ai/ns/cyio/system-configuration#platform_accent_color>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "platform_accent_color");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  platform_background_color: {
    predicate: "<http://darklight.ai/ns/cyio/system-configuration#platform_background_color>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "platform_background_color");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  platform_navigation_color: {
    predicate: "<http://darklight.ai/ns/cyio/system-configuration#platform_navigation_color>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "platform_navigation_color");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  platform_paper_color: {
    predicate: "<http://darklight.ai/ns/cyio/system-configuration#platform_paper_color>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "platform_paper_color");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  platform_primary_color: {
    predicate: "<http://darklight.ai/ns/cyio/system-configuration#platform_primary_color>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "platform_primary_color");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  platform_secondary_color: {
    predicate: "<http://darklight.ai/ns/cyio/system-configuration#platform_secondary_color>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "platform_secondary_color");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  platform_logo: {
    predicate: "<http://darklight.ai/ns/cyio/system-configuration#platform_logo>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:anyURI` : null,  this.predicate, "platform_logo");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  platform_logo_collapsed: {
    predicate: "<http://darklight.ai/ns/cyio/system-configuration#platform_logo_collapsed>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:anyURI` : null,  this.predicate, "platform_logo_collapsed");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  platform_logo_login: {
    predicate: "<http://darklight.ai/ns/cyio/system-configuration#platform_logo_login>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:anyURI` : null,  this.predicate, "platform_logo_logon");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  platform_map_tile_server: {
    predicate: "<http://darklight.ai/ns/cyio/system-configuration#platform_map_tile_server>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:anyURI` : null,  this.predicate, "platform_map_tile_server");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
};

// Serialization schema
export const singularizePlatformThemeSchema = { 
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
    "platform_accent_color": true,
    "platform_background_color": true,
    "platform_navigation_color": true,
    "platform_paper_color": true,
    "platform_primary_color": true,
    "platform_secondary_color": true,
    "platform_logo": true,
    "platform_logo_collapsed": true,
    "platform_logo_login": true,
    "platform_map_tile_server": true,
  }
};
