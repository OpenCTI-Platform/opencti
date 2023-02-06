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
    case 'SETTING':
      return settingsReducer;
    case 'CLUSTER':
      return clusterReducer;
    case 'PLATFORM-MODULE':
      return platformModuleReducer;
    case 'PLATFORM-PROVIDER':
      return platformProviderReducer;
    default:
      throw new CyioError(`Unsupported reducer type ' ${type}'`)
  }
}
    
//
// Reducers
//
const settingsReducer = (item) => {
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
    ...(item.created && { created_at: item.created }),
    ...(item.modified && { updated_at: item.modified }),
    ...(item.name && { platform_title: item.name }),
    ...(item.description && { description: item.description }),
    ...(item.version && { version: item.version }),
    ...(item.platform_favicon && { platform_favicon: item.platform_favicon }),
    ...(item.platform_email && { platform_email: item.platform_email }),
    ...(item.platform_url && { platform_url: item.platform_url }),
    ...(item.platform_language && { platform_language: item.platform_language }),
    ...(item.platform_login_message && { platform_login_message: item.platform_login_message }),
    ...(item.platform_reference_attachment !== undefined && { platform_reference_attachment: item.platform_reference_attachment }),
    ...(item.otp_mandatory !== undefined && { otp_mandatory: item.otp_mandatory }),
    // Mapped to match the existing OpenCTI definition
    ...(item.platform_theme && { platform_theme: item.platform_theme }),
    ...(item.platform_theme_dark_accent_color && { platform_theme_dark_accent_color: item.platform_theme_dark_accent_color }),
    ...(item.platform_theme_dark_background_color && { platform_theme_dark_background_color: item.platform_theme_dark_background_color }),
    ...(item.platform_theme_dark_navigation_color && { platform_theme_dark_navigation_color: item.platform_theme_dark_navigation_color }),
    ...(item.platform_theme_dark_paper_color && { platform_theme_dark_paper_color: item.platform_theme_dark_paper_color}),
    ...(item.platform_theme_dark_primary && { platform_theme_dark_primary: item.platform_theme_dark_primary }),
    ...(item.platform_theme_dark_secondary && { platform_theme_dark_secondary: item.platform_theme_dark_secondary }),
    ...(item.platform_theme_dark_logo && { platform_theme_dark_logo: item.platform_theme_dark_logo }),
    ...(item.platform_theme_dark_logo_collapsed && { platform_theme_dark_logo_collapsed: item.platform_theme_dark_logo_collapsed }),
    ...(item.platform_theme_dark_logo_login && { platform_theme_dark_logo_login: item.platform_theme_dark_logo_login }),
    ...(item.platform_theme_light_accent_color && { platform_theme_light_accent_color: item.platform_theme_light_accent_color }),
    ...(item.platform_theme_light_background_color && { platform_theme_light_background_color: item.platform_theme_light_background_color }),
    ...(item.platform_theme_light_navigation_color && { platform_theme_light_navigation_color: item.platform_theme_light_navigation_color }),
    ...(item.platform_theme_light_paper_color && { platform_theme_light_paper_color: item.platform_theme_light_paper_color}),
    ...(item.platform_theme_light_primary && { platform_theme_light_primary: item.platform_theme_light_primary }),
    ...(item.platform_theme_light_secondary && { platform_theme_light_secondary: item.platform_theme_light_secondary }),
    ...(item.platform_theme_light_logo && { platform_theme_light_logo: item.platform_theme_light_logo }),
    ...(item.platform_theme_light_logo_collapsed && { platform_theme_light_logo_collapsed: item.platform_theme_light_logo_collapsed }),
    ...(item.platform_theme_light_logo_login && { platform_theme_light_logo_login: item.platform_theme_light_logo_login }),
    ...(item.platform_map_tile_server_dark && { platform_map_tile_sever_dark: item.platform_map_tile_server_dark }),
    ...(item.platform_map_tile_server_light && { platform_map_tile_server_light: item.platform_map_tile_server_light }),
    // hints for field-level resolver queries
    ...(item.platform_organization && { platform_organization_iri: item.platform_organization }),
    ...(item.platform_cluster && { platform_cluster_iri: item.platform_cluster }),
    ...(item.platform_modules && { platform_modules_iri: item.modules_theme }),
    ...(item.platform_providers && { platform_providers_iri: item.platform_providers }),
    ...(item.platform_feature_flags && { platform_feature_flags_iri: item.feature_flags }),
    ...(item.platform_theme && { platform_theme_iri: item.platform_theme }),
  }
};

const clusterReducer = (item) => {
  // if no object type was returned, compute the type from the IRI
  if (item.object_type === undefined) {
    if (item.entity_type !== undefined) item.object_type = item.entity_type;
    if (item.iri.includes('cluster-config')) item.object_type = 'cluster-config';
  }

  return {
    iri: item.iri,
    id: item.id,
    ...(item.object_type && { entity_type: item.object_type }),
    ...(item.instances_number && { instances_number: item.instances_number }),
  }
};

const platformModuleReducer = (item) => {
  // if no object type was returned, compute the type from the IRI
  if (item.object_type === undefined) {
    if (item.entity_type !== undefined) item.object_type = item.entity_type;
    if (item.iri.includes('platform-module')) item.object_type = 'platform-module';
  }

  return {
    iri: item.iri,
    id: item.id,
    ...(item.object_type && { entity_type: item.object_type }),
    ...(item.name && { platform_title: item.name }),
    ...(item.description && { description: item.description }),
    ...(item.version && { version: item.version }),
    ...(item.enabled !== undefined && { enabled: item.enabled }),
  }
};

const platformProviderReducer = (item) => {
  // if no object type was returned, compute the type from the IRI
  if (item.object_type === undefined) {
    if (item.entity_type !== undefined) item.object_type = item.entity_type;
    if (item.iri.includes('platform-provider')) item.object_type = 'platform-provider';
  }

  return {
    iri: item.iri,
    id: item.id,
    ...(item.object_type && { entity_type: item.object_type }),
    ...(item.name && { platform_title: item.name }),
    ...(item.description && { description: item.description }),
    ...(item.version && { version: item.version }),
    ...(item.provider_type && { provider_type: item.provider_type }),
    ...(item.strategy && { strategy: item.strategy }),
    ...(item.provider && { provider: item.provider }),
  }
};


// Query Builders


// Predicate Maps
export const settingsPredicateMap = {
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
  platform_organization: {
    predicate: "<http://darklight.ai/ns/cyio/system-configuration#organization>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "platform_organization");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  platform_email: {
    predicate: "<http://darklight.ai/ns/cyio#email_address>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "platform_email");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  platform_favicon: {
    predicate: "<http://darklight.ai/ns/cyio/system-configuration#platform_favicon>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:anyURI` : null,  this.predicate, "platform_favicon");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  platform_cluster: {
    predicate: "<http://darklight.ai/ns/cyio/system-configuration#platform_cluster>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "platform_cluster");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  platform_url: {
    predicate: "<http://darklight.ai/ns/cyio/system-configuration#platform_url>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:anyURI` : null,  this.predicate, "platform_url");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  platform_modules: {
    predicate: "<http://darklight.ai/ns/cyio/system-configuration#platform_modules>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "platform_modules");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  platform_providers: {
    predicate: "<http://darklight.ai/ns/cyio/system-configuration#platform_providers>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "platform_providers");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  platform_language: {
    predicate: "<http://darklight.ai/ns/cyio/system-configuration#platform_language>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "platform_language");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  platform_theme: {
    predicate: "<http://darklight.ai/ns/cyio/system-configuration#platform_theme>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "platform_theme");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  platform_login_message: {
    predicate: "<http://darklight.ai/ns/cyio/system-configuration#platform_login_message>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "platform_login_message");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  platform_enable_reference: {
    predicate: "<http://darklight.ai/ns/cyio/system-configuration#platform_enable_reference>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "platform_enable_reference");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  platform_reference_attachment: {
    predicate: "<http://darklight.ai/ns/cyio/system-configuration#platform_reference_attachment>",
    binding: function (iri, value) { return parameterizePredicate(iri, value !== undefined  ? `"${value}"^^xsd:boolean` : null,  this.predicate, "platform_reference_attachment");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  platform_feature_flags: {
    predicate: "<http://darklight.ai/ns/cyio/system-configuration#platform_feature_flags>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "platform_feature_flags");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  otp_mandatory: {
    predicate: "<http://darklight.ai/ns/cyio/system-configuration#otp_mandatory>",
    binding: function (iri, value) { return parameterizePredicate(iri, value !== undefined  ? `"${value}"^^xsd:boolean` : null,  this.predicate, "otp_mandatory");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  // Predicate paths to map to nested objects

};

export const clusterPredicateMap = {
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
  instances_number: {
    predicate: "<http://darklight.ai/ns/cyio/system-configuration#instances_number>",
    binding: function (iri, value) { return parameterizePredicate(iri, value !== undefined ? `"${value}"^^xsd:nonNegativeInteger` : null,  this.predicate, "instances_number");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
};

export const platformModulePredicateMap = {
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
  enabled: {
    predicate: "<http://darklight.ai/ns/cyio/system-configuration#enabled>",
    binding: function (iri, value) { return parameterizePredicate(iri, value !== undefined ? `"${value}"^^xsd:boolean` : null,  this.predicate, "enabled");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
};

export const platformProviderPredicateMap = {
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
  provider_type: {
    predicate: "<http://darklight.ai/ns/cyio/system-configuration#provider_type>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "provider_type");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  strategy: {
    predicate: "<http://darklight.ai/ns/cyio/system-configuration#strategy>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "strategy");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  provider: {
    predicate: "<http://darklight.ai/ns/cyio/system-configuration#provider>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "provider");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
};
  
// Serialization schema
export const singularizeSettingsSchema = { 
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
    "platform_organization": true,  //??
    "platform_title": true,         // ??
    "platform_favicon": true,
    "platform_email": true,
    "platform_cluster": true,
    "platform_url": true,
    "platform_language": true,
    "platform_theme": true,
    // Mapped predicate paths
    "platform_theme_dark_background": true,
    "platform_theme_dark_paper": true,
    "platform_theme_dark_nav": true,
    "platform_theme_dark_primary": true,
    "platform_theme_dark_secondary": true,
    "platform_theme_dark_accent": true,
    "platform_theme_dark_logo": true,
    "platform_theme_dark_logo_collapsed": true,
    "platform_theme_dark_logo_login": true,
    "platform_theme_light_background": true,
    "platform_theme_light_paper": true,
    "platform_theme_light_nav": true,
    "platform_theme_light_primary": true,
    "platform_theme_light_secondary": true,
    "platform_theme_light_accent": true,
    "platform_theme_light_logo": true,
    "platform_theme_light_logo_collapsed": true,
    "platform_theme_light_logo_login": true,
    "platform_map_tile_server_dark": true,
    "platform_map_tile_server_light": true,
    "platform_login_message": true,
    "platform_reference_attachment": true,
    "otp_mandatory": true,
  }
};

export const singularizeClusterConfigSchema = { 
  singularizeVariables: {
    "": false, // so there is an object as the root instead of an array
    "id": true,
    "iri": true,
    "object_type": true,
    "entity_type": true,
    "instances_number": true,
  }
};

export const singularizePlatformModuleSchema = { 
  singularizeVariables: {
    "": false, // so there is an object as the root instead of an array
    "id": true,
    "iri": true,
    "object_type": true,
    "entity_type": true,
    "name": true,
    "description": true,
    "version": true,
    "enabled": true,
  }
};

export const singularizePlatformProviderSchema = { 
  singularizeVariables: {
    "": false, // so there is an object as the root instead of an array
    "id": true,
    "iri": true,
    "object_type": true,
    "entity_type": true,
    "name": true,
    "description": true,
    "version": true,
    "provider_type": true,
    "strategy": true,
    "provider": true,
  }
};
