import { UserInputError } from 'apollo-server-errors';
import { 
  optionalizePredicate, 
  parameterizePredicate, 
  buildSelectVariables, 
  attachQuery,
  detachQuery,
  generateId, 
  DARKLIGHT_NS,
  checkIfValidUUID,
} from '../../../utils.js';
  
  // Reducer Selection
export function getReducer(type) {
  switch (type) {
    case 'INFORMATION-SYSTEM':
      return informationSystemReducer;
    default:
      throw new UserInputError(`Unsupported reducer type ' ${type}'`)
  }
}
    
//
// Reducers
//
const informationSystemReducer = (item) => {
  // if no object type was returned, compute the type from the IRI
  if (item.object_type === undefined) {
      if (item.entity_type !== undefined) item.object_type = item.entity_type;
      if (item.iri.includes('information-system')) item.object_type = 'information-system';
  }

  return {
      iri: item.iri,
      id: item.id,
      ...(item.object_type && { entity_type: item.object_type }),
      ...(item.created && { created: item.created }),
      ...(item.modified && { modified: item.modified }),
      ...(item.component_type && { component_type: item.component_type }),
      ...(item.purpose && { purpose: item.purpose }),
      ...(item.system_ids && { system_ids: item.system_ids }),
      ...(item.system_name && { system_name: item.system_name }),
      ...(item.short_name && {short_name: item.short_name }),
      ...(item.description && { description: item.description }),
      ...(item.identity_assurance_level && { identity_assurance_level: item.identity_assurance_level }),
      ...(item.authenticator_assurance_level && { authenticator_assurance_level: item.authenticator_assurance_level }),
      ...(item.federation_assurance_level && { federation_assurance_level: item.federation_assurance_level }),
      ...(item.deployment_model && { deployment_model: item.deployment_model }),
      ...(item.cloud_service_model && { cloud_service_model: item.cloud_service_model }),
      ...(item.date_authorized && { date_authorized: item.date_authorized }),
      ...(item.security_sensitivity_level && { security_sensitivity_level: item.security_sensitivity_level }),
      ...(item.privacy_designation !== undefined && {privacy_designation: item.privacy_designation }),
      ...(item.security_objective_confidentiality && { security_objective_confidentiality: item.security_objective_confidentiality }),
      ...(item.security_objective_integrity && { security_objective_integrity: item.security_objective_integrity }),
      ...(item.security_objective_availability && { security_objective_availability: item.security_objective_availability }),
      ...(item.operational_status && { operational_status: item.operational_status }),
      // hints for field-level resolver queries
      ...(item.information_types && {information_type_iris: item.information_types}),
      ...(item.authorization_boundary && { authorization_boundary_iri: item.authorization_boundary }),
      ...(item.network_architecture && { network_architecture_iri: item.network_architecture }),
      ...(item.data_flow && { data_flow_iri: item.data_flow }),
      ...(item.system_implementation && { system_implementation_iri: item.system_implementation }),
      // Use instead of system_implementation as the elements are base properties on InformationSystem
      ...(item.components && { component_iris: item.components }),
      ...(item.inventory_items && { inventory_item_iris: item.inventory_items }),
      ...(item.leveraged_authorizations && { leveraged_authorization_iris: item.leveraged_authorizations }),
      ...(item.users && { users_iris: item.users }),
      // hints for general lists of items
      ...(item.responsible_parties && { responsible_party_iris: item.responsible_parties }),
      ...(item.labels && { label_iris: item.labels }),
      ...(item.links && { link_iris: item.links }),
      ...(item.remarks && { remark_iris: item.remarks }),
      // hints for retrieving risk count and highest severity
      ...(item.related_risks && { related_risks_iri: item.related_risks }),
      ...(item.risk_count !== undefined && { risk_count: item.risk_count }),
      ...(item.risk_score !== undefined && { risk_score: item.risk_score }),
      ...(item.top_risk_severity && { top_risk_severity: item.top_risk_severity }),
    }
};


// Utility
export const getInformationTypeIri = (id) => {
  if (!checkIfValidUUID(id)) throw new UserInputError(`Invalid identifier: ${id}`);
  return `<http://cyio.darklight.ai/information-system--${id}>`;
}

// Query Builders - Information System
export const selectInformationSystemQuery = (id, select) => {
  return selectInformationSystemByIriQuery(`http://cyio.darklight.ai/information-system--${id}`, select);
}

export const selectInformationSystemByIriQuery = (iri, select) => {
  if (!iri.startsWith('<')) iri = `<${iri}>`;
  if (select === undefined || select === null) select = Object.keys(informationSystemPredicateMap);

  // this is needed to assist in the determination of the type of the data source
  if (!select.includes('id')) select.push('id');
  if (!select.includes('object_type')) select.push('object_type');
  if (!select.includes('component_type')) select.push('component_type');
  if (!select.includes('information_types')) select.push('information_types');
  if (select.includes('system_implementation')) {
    select.push('components');
    select.push('inventory_items');
    select.push('leveraged_authorizations');
    select.push('users');
    select = select.filter((i) => i !== 'system_implementation');    
  }

  // define related risks clause to restrict to only Risk since it available in other objects
  let relatedRiskClause = '', relatedRiskVariable = '';
  if (select.includes('related_risks')) {
    select = select.filter((i) => i !== 'related_risks');  
    relatedRiskVariable = '?related_risks';
    let predicate = informationSystemPredicateMap['related_risks'].binding('?iri');
    relatedRiskClause = `
    OPTIONAL {
      ${predicate} .
      FILTER REGEX(str(?related_risks), "#Risk", "i")
    }`;
  }
  
  const { selectionClause, predicates } = buildSelectVariables(informationSystemPredicateMap, select);

  return `
  SELECT ?iri ${selectionClause} ${relatedRiskVariable}
  FROM <tag:stardog:api:context:local>
  WHERE {
    BIND(${iri} AS ?iri)
    ?iri a <http://csrc.nist.gov/ns/oscal/info-system#InformationSystem> .
    ${predicates}
    ${relatedRiskClause}
    {
      SELECT DISTINCT ?iri
      WHERE {
          ?inventory a <http://csrc.nist.gov/ns/oscal/common#AssetInventory> ;
              <http://csrc.nist.gov/ns/oscal/common#assets> ?iri .
      }
    }
  }`
}

export const selectAllInformationSystemsQuery = (select, args, parent) => {
  if (select === undefined || select === null) select = Object.keys(informationSystemPredicateMap);
  if (!select.includes('id')) select.push('id');
  if (!select.includes('object_type')) select.push('object_type');
  if (!select.includes('component_type')) select.push('component_type');
  if (!select.includes('information_types')) select.push('information_types');
  if (select.includes('system_implementation')) {
    select.push('components');
    select.push('inventory_items');
    select.push('leveraged_authorizations');
    select.push('users');
    select = select.filter((i) => i !== 'system_implementation');    
  }

  if (args !== undefined ) {
    if ( args.filters !== undefined ) {
      for( const filter of args.filters) {
        if (!select.includes(filter.key)) select.push( filter.key );
      }
    }
    
    // add value of orderedBy's key to cause special predicates to be included
    if ( args.orderedBy !== undefined ) {
      if (!select.includes(args.orderedBy)) select.push(args.orderedBy);
    }
  }

  // define related risks clause to restrict to only Risk since it available in other objects
  let relatedRiskClause = '', relatedRiskVariable = '';
  if (select.includes('top_risk_severity') || select.includes('risk_count') || select.includes('related_risks')) {
    if (select.includes('related_risks')) select = select.filter((i) => i !== 'related_risks');    
    let predicate = informationSystemPredicateMap['related_risks'].binding('?iri');
    relatedRiskVariable = '?related_risks';
    relatedRiskClause = `
    OPTIONAL {
      ${predicate} .
      FILTER REGEX(str(?related_risks), "#Risk", "i")
    }`;
  }

  // build lists of selection variables and predicates
  const { selectionClause, predicates } = buildSelectVariables(informationSystemPredicateMap, select);

  return `
  SELECT DISTINCT ?iri ${selectionClause} ${relatedRiskVariable}
  FROM <tag:stardog:api:context:local>
  WHERE {
    ?iri a <http://csrc.nist.gov/ns/oscal/info-system#InformationSystem> . 
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
  `
}

export const insertInformationSystemQuery = (propValues) => {
  let id_material;
  if (!propValues.system_ids && propValues.system_name) {
    id_material = {...(propValues.system_name && {"system_name": propValues.system_name})};
    propValues.system_ids = [generateId(id_material, DARKLIGHT_NS)];
  }
  id_material = {
    ...(propValues.system_name && {"system_name": propValues.system_name}),
  } ;
  const id = generateId( id_material, DARKLIGHT_NS );
  const timestamp = new Date().toISOString();

  // determine the appropriate ontology class type
  const iri = `<http://cyio.darklight.ai/information-system--${id}>`;
  const insertPredicates = [];
  Object.entries(propValues).forEach((propPair) => {
    if (informationSystemPredicateMap.hasOwnProperty(propPair[0])) {
      if (Array.isArray(propPair[1])) {
        for (let value of propPair[1]) {
          insertPredicates.push(informationSystemPredicateMap[propPair[0]].binding(iri, value));
        }  
      } else {
        insertPredicates.push(informationSystemPredicateMap[propPair[0]].binding(iri, propPair[1]));
      }
    }
  });

  const query = `
  INSERT DATA {
    GRAPH ${iri} {
      ${iri} a <http://csrc.nist.gov/ns/oscal/info-system#InformationSystem> .
      ${iri} a <http://csrc.nist.gov/ns/oscal/common#Component> .
      ${iri} a <http://csrc.nist.gov/ns/oscal/common#Object> .
      ${iri} a <http://scap.nist.gov/ns/asset-identification#System> .
      ${iri} a <http://scap.nist.gov/ns/asset-identification#ItAsset> .
      ${iri} a <http://scap.nist.gov/ns/asset-identification#Asset> .
      ${iri} a <http://darklight.ai/ns/common#Object> .
      ${iri} <http://darklight.ai/ns/common#id> "${id}" .
      ${iri} <http://darklight.ai/ns/common#object_type> "information-system" . 
      ${iri} <http://darklight.ai/ns/common#created> "${timestamp}"^^xsd:dateTime . 
      ${iri} <http://darklight.ai/ns/common#modified> "${timestamp}"^^xsd:dateTime . 
      ${insertPredicates.join(" . \n")}
    }
  }
  `;
  return {iri, id, query}
}
    
export const deleteInformationSystemQuery = (id) => {
  const iri = `http://cyio.darklight.ai/information-system--${id}`;
  return deleteInformationSystemByIriQuery(iri);
}

export const deleteInformationSystemByIriQuery = (iri) => {
  if (!iri.startsWith('<')) iri = `<${iri}>`;
  return `
  DELETE {
    GRAPH ${iri} {
      ?iri ?p ?o
    }
  } WHERE {
    GRAPH ${iri} {
      ?iri a <http://csrc.nist.gov/ns/oscal/info-system#InformationSystem> .
      ?iri ?p ?o
    }
  }
  `
}

export const deleteMultipleInformationSystemsQuery = (ids) =>{
  const values = ids ? (ids.map((id) => `"${id}"`).join(' ')) : "";
  return `
  DELETE {
    GRAPH ?g {
      ?iri ?p ?o
    }
  } WHERE {
    GRAPH ?g {
      ?iri a <http://csrc.nist.gov/ns/oscal/info-system#InformationSystem> .
      ?iri <http://darklight.ai/ns/common#id> ?id .
      ?iri ?p ?o .
      VALUES ?id {${values}}
    }
  }
  `
}

export const attachToInformationSystemQuery = (id, field, itemIris) => {
  if (!informationSystemPredicateMap.hasOwnProperty(field)) return null;
  const iri = `<http://cyio.darklight.ai/information-system--${id}>`;
  const predicate = informationSystemPredicateMap[field].predicate;

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

  return attachQuery(iri, statements, informationSystemPredicateMap, '<http://csrc.nist.gov/ns/oscal/info-system#InformationSystem>');
}

export const detachFromInformationSystemQuery = (id, field, itemIris) => {
  const iri = `<http://cyio.darklight.ai/information-system--${id}>`;
  if (!informationSystemPredicateMap.hasOwnProperty(field)) return null;
  const predicate = informationSystemPredicateMap[field].predicate;
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

  return detachQuery(iri, statements, informationSystemPredicateMap, '<http://csrc.nist.gov/ns/oscal/info-system#InformationSystem>');
}
  
  
// Predicate Maps
export const informationSystemPredicateMap = {
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
  component_type: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#component_type>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "component_type");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  purpose: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#purpose>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"@en-US`: null, this.predicate, "purpose");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  system_ids: {
    predicate: "<http://csrc.nist.gov/ns/oscal/info-system#system_ids>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "system_ids");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  system_name: {
    predicate: "<http://csrc.nist.gov/ns/oscal/info-system#system_name>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "system_name");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  short_name: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#short_name>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "short_name");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  description: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#description>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"@en-US`: null, this.predicate, "description");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  deployment_model: {
    predicate: "<http://csrc.nist.gov/ns/oscal/info-system#deployment_model>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "deployment_model");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  cloud_service_model: {
    predicate: "<http://csrc.nist.gov/ns/oscal/info-system#cloud_service_model>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "cloud_service_model");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  operational_status: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#operational_status>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "operational_status");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  date_authorized: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#date_authorized>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:date`: null, this.predicate, "date_authorized");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  responsible_parties: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#responsible_parties>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "responsible_parties");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  information_types: {
    predicate: "<http://csrc.nist.gov/ns/oscal/info-system#information_types>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "information_types");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  components: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#components>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "components");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  inventory_items: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#inventory_items>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "inventory_items");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  leveraged_authorizations: {
    predicate: "<http://csrc.nist.gov/ns/oscal/info-system#leveraged_authorizations>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "leveraged_authorizations");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  users: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#users>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "users");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  identity_assurance_level: {
    predicate: "<http://csrc.nist.gov/ns/oscal/info-system#identity_assurance_level>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "identity_assurance_level");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  authenticator_assurance_level: {
    predicate: "<http://csrc.nist.gov/ns/oscal/info-system#authenticator_assurance_level>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "authenticator_assurance_level");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  federation_assurance_level: {
    predicate: "<http://csrc.nist.gov/ns/oscal/info-system#federation_assurance_level>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "federation_assurance_level");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  security_sensitivity_level: {
    predicate: "<http://csrc.nist.gov/ns/oscal/info-system#security_sensitivity_level>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "security_sensitivity_level");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  security_objective_confidentiality: {
    predicate: "<http://csrc.nist.gov/ns/oscal/info-system#security_objective_confidentiality>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "security_objective_confidentiality");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  security_objective_integrity: {
    predicate: "<http://csrc.nist.gov/ns/oscal/info-system#security_objective_integrity>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "security_objective_integrity");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  security_objective_availability: {
    predicate: "<http://csrc.nist.gov/ns/oscal/info-system#security_objective_availability>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "security_objective_availability");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  privacy_designation: {
    predicate: "<http://csrc.nist.gov/ns/oscal/info-system#privacy_designation>",
    binding: function (iri, value) { return parameterizePredicate(iri, value !== undefined ? `"${value}"^^xsd:boolean`: null, this.predicate, "privacy_designation");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  authorization_boundary: {
    predicate: "<http://csrc.nist.gov/ns/oscal/info-system#authorization_boundary>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "authorization_boundary");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  network_architecture: {
    predicate: "<http://csrc.nist.gov/ns/oscal/info-system#network_architecture>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "network_architecture");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  data_flow: {
    predicate: "<http://csrc.nist.gov/ns/oscal/info-system#data_flow>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "data_flow");},
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
  links: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#links>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "links");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  remarks: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#remarks>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "remarks");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  // related_risks: {
  //   predicate: "^<http://csrc.nist.gov/ns/oscal/assessment/common#subject_ref>/^<http://csrc.nist.gov/ns/oscal/assessment/common#subjects>/^<http://csrc.nist.gov/ns/oscal/assessment/common#related_observations>",
  //   binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, "related_risks");},
  //   optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  // },
};

export const systemImplementationPredicateMap = {
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
  components: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#components>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "components");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  inventory_items: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#inventory_items>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "inventory_items");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  leveraged_authorizations: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#leveraged_authorizations>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "leveraged_authorizations");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  users: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#users>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "users");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  links: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#links>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "links");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  remarks: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#remarks>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "remarks");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
};


// Serialization schema
export const singularizeInformationSystemSchema = { 
  singularizeVariables: {
    "": false, // so there is an object as the root instead of an array
    "id": true,
    "iri": true,
    "object_type": true,
    "entity_type": true,
    "created": true,
    "modified": true,
    "component_type": true,
    "purpose": true,
    "system_name": true,
    "short_name": true,
    "description": true,
    "deployment_model": false,
    "cloud_service_model": true,
    "operational_status": true,
    "date_authorized": true,
    "responsible_parties": false,
    "information_types": false,
    "system_implementation": true,
    "relationships": false,
    "identity_assurance_level": true,
    "authenticator_assurance_level": true,
    "federation_assurance_level": true,
    "security_sensitivity_level": true,
    "security_objective_confidentiality": true,
    "security_objective_integrity": true,
    "security_objective_availability": true,
    "privacy_designation": true,
    "authorization_boundary": true,
    "network_architecture": true,
    "data_flow": true,
  }
};

export const singularizeSystemImplementationSchema = { 
  singularizeVariables: {
    "": false, // so there is an object as the root instead of an array
    "id": true,
    "iri": true,
    "object_type": true,
    "entity_type": true,
    "created": true,
    "modified": true,
    "components": false,
    "inventory_items": false,
    "leveraged_authorizations": false,
    "users": false,
  }
};
