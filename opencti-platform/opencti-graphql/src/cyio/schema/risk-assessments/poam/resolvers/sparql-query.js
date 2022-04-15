import {optionalizePredicate, parameterizePredicate, buildSelectVariables, generateId, OSCAL_NS} from "../../../utils.js";

export function getReducer( type ) {
  switch( type ) {
    case 'POAM':
      return poamReducer;
    case 'POAM-ITEM':
      return poamItemReducer;
    case 'POAM-LOCAL-DEFINITION':
      return poamLocalDefReducer;
    default:
      throw new Error(`Unsupported reducer type ' ${type}'`)
  }
}


// Reducers
const poamReducer = (item) => {
  // if no object type was returned, compute the type from the IRI
  if ( item.object_type === undefined ) {
    item.object_type = 'poam';
  }

  return {
    id: item.id,
    standard_id: item.id,
    ...(item.object_type && {"entity_type": item.object_type}),
    ...(item.created && {"created": item.created}),
    ...(item.modified && {"modified": item.modified}),
    // Metadata
    ...(item.name && {"name": item.name} ),
    ...(item.published && {"published": item.published}),
    ...(item.last_modified && {"last_modified": item.last_modified}),
    ...(item.version && {"version": item.version}),
    ...(item.oscal_version && {"oscal_version": item.oscal_version}),
    ...(item.revisions && {revisions_iri: item.revisions}),
    ...(item.document_ids && {doc_id_iri: item.document_ids}),
    ...(item.roles && {roles_iri: item.roles}),
    ...(item.locations && {locations_iri: item.locations}),
    ...(item.parties && {parties_iri:item_parties}),
    ...(item.responsible_parties && {resp_parties_iri: item.responsible_parties}),
    ...(item.labels && {labels_iri: item.labels}),
    ...(item.links && {links_iri: item.links}),
    ...(item.remarks && {remarks_iri: item.remarks}),
    ...(item.relationships && {relationship_iri: item.relationships}),
    // POAM
    ...(item.ssp && {ssp_iri: item.ssp}),
    ...(item.system_id && {system_id: item.system_id}),
    ...(item.system_identifier_type && {system_identifier_type: item.system_identifier_type}),
    ...(item.local_definitions && {local_definitions_iri: item.local_definitions}),
    ...(item.observations && {observations_iri: item.observations}),
    ...(item.risks && {risks_iri: item.risks}),
    ...(item.poam_items && {poam_items_iri: item.poam_items}),
    //Backmatter
    ...(item.resources && {resources_iri: item.resources}),
  }
}
const poamItemReducer = (item) => {
  // if no object type was returned, compute the type from the IRI
  if ( item.object_type === undefined ) {
    item.object_type = 'poam-item';
  }

  return {
    id: item.id,
    standard_id: item.id,
    ...(item.object_type && {"entity_type": item.object_type}),
    ...(item.created && {"created": item.created}),
    ...(item.modified && {"modified": item.modified}),
    // Finding
    ...(item.name && {"name": item.name} ),
    ...(item.description && {"description": item.description}),
    ...(item.origins && {origins_iri: item.origins}),
    ...(item.related_observations && {related_observations_iri: item.related_observations}),
    ...(item.related_risks && {related_risks_iri: item.related_risks}),
    ...(item.labels && {labels_iri: item.labels}),
    ...(item.links && {links_iri: item.links}),
    ...(item.remarks && {remarks_iri: item.remarks}),
    ...(item.relationships && {relationship_iri: item.relationships}),
    // POAM Item
    ...(item.poam_id && {poam_id: item.poam_id}),
    ...(item.accepted_risk !== undefined && {accepted_risk: item.accepted_risk})
  }
}
const poamLocalDefReducer = (item) => {
  // if no object type was returned, compute the type from the IRI
  if ( item.object_type === undefined ) {
    item.object_type = 'poam-local-definition';
  }

  return {
    id: item.id,
    standard_id: item.id,
    ...(item.object_type && {"entity_type": item.object_type}),
    // Local Definition
    ...(item.components && {components_iri: item.components}),
    ...(item.inventory_items && {inventory_items_iri: item.inventory_items}),
    ...(item.remarks && {remarks_iri: item.remarks}),
  }
}

//Predicate Maps
export const poamPredicateMap = {
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
  // relationships: {
  //   predicate: "<http://darklight.ai/ns/common#relationships>",
  //   binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "relationships");},
  //   optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  // },
  name: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#name>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "name");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  description: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#description>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "description");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  published: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#published>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime` : null,  this.predicate, "published");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  last_modified: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#last_modified>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime` : null,  this.predicate, "last_modified");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  version: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#version>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "version");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  oscal_version: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#oscal_version>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "oscal_version");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  revisions: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#revisions>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "revisions");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  document_ids: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#document_ids>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "document_ids");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  roles: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#roles>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "roles");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  locations: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#locations>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "locations");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  parties: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#parties>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "parties");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  resources: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#resources>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "resources");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  responsible_parties: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#responsible_parties>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "responsible_parties");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  ssp: {
    predicate: "<http://csrc.nist.gov/ns/oscal/poam#ssp>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "ssp");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  system_id: {
    predicate: "<http://csrc.nist.gov/ns/oscal/poam#system_id>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "system_id");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  system_identifier_type: {
    predicate: "<http://csrc.nist.gov/ns/oscal/poam#system_identifier_type>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:anyURI` : null,  this.predicate, "system_identifier_type");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  local_definitions: {
    predicate: "<http://csrc.nist.gov/ns/oscal/poam#local_definitions>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "local_definitions");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  observations: {
    predicate: "<http://csrc.nist.gov/ns/oscal/poam#observations>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "observations");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  risks: {
    predicate: "<http://csrc.nist.gov/ns/oscal/poam#risks>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "risks");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  poam_items: {
    predicate: "<http://csrc.nist.gov/ns/oscal/poam#poam_items>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "poam_items");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
}
export const poamItemPredicateMap = {
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
  // relationships: {
  //   predicate: "<http://darklight.ai/ns/common#relationships>",
  //   binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "relationships");},
  //   optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  // },
  name: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#name>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "name");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  description: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#description>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "description");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  origins: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#origins>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "origins");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  related_observations: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#related_observations>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "related_observations");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  related_risks: {
    predicate: "<http://csrc.nist.gov/ns/oscal/assessment/common#related_risks>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "related_risks");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  poam_id: {
    predicate: "<http://fedramp.gov/ns/oscal#poam_id>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "poam_id");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  accepted_risk: {
    predicate: "<http://darklight.ai/ns/oscal#accepted_risk>",
    binding: function (iri, value) { return parameterizePredicate(iri, value !== undefined ? `"${value}"^^xsd:boolean` : null, this.predicate, "accepted_risk")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));}
  },
}
export const poamLocalDefinitionPredicateMap = {
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
  remarks: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#remarks>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "remarks");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  components: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#components>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "components");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  inventory_items: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#inventory_items>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "inventory_items");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
}


// POAM support functions
export const insertPOAMQuery = (propValues) => {
  const id_material = {
    ...(propValues.system_id && {"system_id": propValues.system_id}),
    ...(propValues.system_identifier_type && {"system_identifier_type": propValues.system_identifier_type}),
  } ;
  const id = generateId( id_material, OSCAL_NS );
  const timestamp = new Date().toISOString()
  const iri = `<http://csrc.nist.gov/ns/oscal/common#POAM-${id}>`;
  const insertPredicates = Object.entries(propValues)
      .filter((propPair) => poamPredicateMap.hasOwnProperty(propPair[0]))
      .map((propPair) => poamPredicateMap[propPair[0]].binding(iri, propPair[1]))
      .join('. \n      ');
  const query = `
  INSERT DATA {
    GRAPH ${iri} {
      ${iri} a <http://csrc.nist.gov/ns/oscal/common#POAM> .
      ${iri} a <http://csrc.nist.gov/ns/oscal/common#Model> .
      ${iri} a <http://csrc.nist.gov/ns/oscal/common#Object> .
      ${iri} a <http://darklight.ai/ns/common#Object> .
      ${iri} <http://darklight.ai/ns/common#id> "${id}" .
      ${iri} <http://darklight.ai/ns/common#object_type> "poam" . 
      ${iri} <http://darklight.ai/ns/common#created> "${timestamp}"^^xsd:dateTime . 
      ${iri} <http://darklight.ai/ns/common#modified> "${timestamp}"^^xsd:dateTime . 
      ${insertPredicates}
    }
  }
  `;
  return {iri, id, query}
}
export const selectPOAMQuery = (id, select) => {
  return selectPOAMByIriQuery(`http://csrc.nist.gov/ns/oscal/common#POAM-${id}`, select);
}
export const selectPOAMByIriQuery = (iri, select) => {
  if (!iri.startsWith('<')) iri = `<${iri}>`;
  if (select === null) select = Object.keys(poamPredicateMap);
  const { selectionClause, predicates } = buildSelectVariables(poamPredicateMap, select);
  return `
  SELECT ${selectionClause}
  FROM <tag:stardog:api:context:local>
  WHERE {
    BIND(${iri} AS ?iri)
    ?iri a <http://csrc.nist.gov/ns/oscal/common#POAM> .
    ${predicates}
  }
  `
}
export const selectAllPOAMs = (select, filters) => {
  if (select === null) select =Object.keys(poamPredicateMap);

  // add value of filter's key to cause special predicates to be included
  if ( filters !== undefined ) {
    for( const filter of filters) {
      if (!select.hasOwnProperty(filter.key)) select.push( filter.key );
    }
  }

  const { selectionClause, predicates } = buildSelectVariables(poamPredicateMap, select);
  return `
  SELECT DISTINCT ?iri ${selectionClause} 
  FROM <tag:stardog:api:context:local>
  WHERE {
    ?iri a <http://csrc.nist.gov/ns/oscal/common#POAM> . 
    ${predicates}
  }
  `
}
export const deletePOAMQuery = (id) => {
  const iri = `http://csrc.nist.gov/ns/oscal/common#POAM-${id}`;
  return deletePOAMByIriQuery(iri);
}
export const deletePOAMByIriQuery = (iri) =>  {
  return `
  DELETE {
    GRAPH <${iri}> {
      ?iri ?p ?o
    }
  } WHERE {
    GRAPH <${iri}> {
      ?iri a <http://csrc.nist.gov/ns/oscal/common#POAM> .
      ?iri ?p ?o
    }
  }
  `
}
export const addItemToPOAM = (poamId, itemIri) => {
  const poamIri = `<http://csrc.nist.gov/ns/oscal/common#POAM-${poamId}>`;
  return `
  INSERT DATA {
    GRAPH ${poamIri} {
      ${poamIri} <http://csrc.nist.gov/ns/oscal/poam#poam_items> ${itemIri}
    }
  }
  `
}
export const removeItemFromPOAM = (poamId, id) => {
  const poamIri = `<http://csrc.nist.gov/ns/oscal/common#POAM-${poamId}>`;
  return `
  DELETE DATA {
    GRAPH ${poamIri} {
      ${poamIri} <http://csrc.nist.gov/ns/oscal/poam#poam_items> <http://csrc.nist.gov/ns/oscal/poam#Item-${id}> .
    }
  }
  `
}
export const attachToPOAMQuery = (id, field, itemIris) => {
  const iri = `<http://csrc.nist.gov/ns/oscal/common#POAM-${id}>`;
  if (!poamPredicateMap.hasOwnProperty(field)) return null;
  const predicate = poamPredicateMap[field].predicate;
  let statements;
  if (Array.isArray(itemIris)) {
    statements = itemIris
      .map((itemIri) => `${iri} ${predicate} ${itemIri}`)
      .join(".\n        ")
    }
  else {
    statements = `${iri} ${predicate} ${itemIris}`;
  }
  return `
  INSERT DATA {
    GRAPH ${iri} {
      ${statements}
    }
  }
  `
}
export const detachFromPOAMQuery = (id, field, itemIris) => {
  const iri = `<http://csrc.nist.gov/ns/oscal/common#POAM-${id}>`;
  if (!poamPredicateMap.hasOwnProperty(field)) return null;
  const predicate = poamPredicateMap[field].predicate;
  let statements;
  if (Array.isArray(itemIris)) {
    statements = itemIris
      .map((itemIri) => `${iri} ${predicate} ${itemIri}`)
      .join(".\n        ")
    }
  else {
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

// POAM Item support functions
export const insertPOAMItemQuery = (propValues) => {
  const id_material = {
    ...(propValues.name && {"name": propValues.name}),
  } ;
  const id = generateId( id_material, OSCAL_NS );
  const timestamp = new Date().toISOString()
  const iri = `<http://csrc.nist.gov/ns/oscal/poam#Item-${id}>`;
  const insertPredicates = Object.entries(propValues)
      .filter((propPair) => poamItemPredicateMap.hasOwnProperty(propPair[0]))
      .map((propPair) => poamItemPredicateMap[propPair[0]].binding(iri, propPair[1]))
      .join('. \n      ');
  const query = `
  INSERT DATA {
    GRAPH ${iri} {
      ${iri} a <http://csrc.nist.gov/ns/oscal/poam#Item> .
      ${iri} a <http://csrc.nist.gov/ns/oscal/assessment/common#Finding> .
      ${iri} a <http://csrc.nist.gov/ns/oscal/common#Object> .
      ${iri} a <http://darklight.ai/ns/common#Object> .
      ${iri} <http://darklight.ai/ns/common#id> "${id}".
      ${iri} <http://darklight.ai/ns/common#object_type> "poam-item" . 
      ${iri} <http://darklight.ai/ns/common#created> "${timestamp}"^^xsd:dateTime . 
      ${iri} <http://darklight.ai/ns/common#modified> "${timestamp}"^^xsd:dateTime . 
      ${insertPredicates}
    }
  }
  `;
  return {iri, id, query}
}
export const selectPOAMItemQuery = (id, select) => {
  return selectPOAMItemByIriQuery(`http://csrc.nist.gov/ns/oscal/poam#Item-${id}`, select);
}
export const selectPOAMItemByIriQuery = (iri, select) => {
  if (!iri.startsWith('<')) iri = `<${iri}>`;
  if (select === null) select = Object.keys(poamItemPredicateMap);
  const { selectionClause, predicates } = buildSelectVariables(poamItemPredicateMap, select);
  return `
  SELECT ${selectionClause}
  FROM <tag:stardog:api:context:local>
  WHERE {
    BIND(${iri} AS ?iri)
    ?iri a <http://csrc.nist.gov/ns/oscal/poam#Item> .
    ${predicates}
  }
  `
}
export const selectAllPOAMItems = (select, filters) => {
  if (select === null) select =Object.keys(poamItemPredicateMap);
  
  // add value of filter's key to cause special predicates to be included
  if ( filters !== undefined ) {
    for( const filter of filters) {
      if (!select.hasOwnProperty(filter.key)) select.push( filter.key );
    }
  }

  const { selectionClause, predicates } = buildSelectVariables(poamItemPredicateMap, select);
  return `
  SELECT DISTINCT ?iri ${selectionClause} 
  FROM <tag:stardog:api:context:local>
  WHERE {
    ?iri a <http://csrc.nist.gov/ns/oscal/poam#Item> . 
    ${predicates}
  }
  `
}
export const deletePOAMItemQuery = (id) => {
  const iri = `http://csrc.nist.gov/ns/oscal/poam#Item-${id}`;
  return deletePOAMItemByIriQuery(iri);
}
export const deletePOAMItemByIriQuery = (iri) => {
  return `
  DELETE {
    GRAPH <${iri}> {
      ?iri ?p ?o
    }
  } WHERE {
    GRAPH <${iri}> {
      ?iri a <http://csrc.nist.gov/ns/oscal/poam#Item> .
      ?iri ?p ?o
    }
  }
  `
}
export const deleteItemQuery = (id) => {
  return `
  DELETE {
    GRAPH ?g{
      ?iri ?p ?o
    }
  } WHERE {
    GRAPH ?g{
      ?iri a <http://csrc.nist.gov/ns/oscal/poam#Item> .
      ?iri <http://darklight.ai/ns/common#id> "${id}". 
      ?iri ?p ?o
    }
  }
  `
}
export const attachToPOAMItemQuery = (id, field, itemIris) => {
  const iri = `<http://csrc.nist.gov/ns/oscal/poam#Item-${id}>`;
  if (!poamItemPredicateMap.hasOwnProperty(field)) return null;
  const predicate = poamItemPredicateMap[field].predicate;
  let statements;
  if (Array.isArray(itemIris)) {
    statements = itemIris
      .map((itemIri) => `${iri} ${predicate} ${itemIri}`)
      .join(".\n        ")
    }
  else {
    statements = `${iri} ${predicate} ${itemIris}`;
  }
  return `
  INSERT DATA {
    GRAPH ${iri} {
      ${statements}
    }
  }
  `
}
export const detachFromPOAMItemQuery = (id, field, itemIri) => {
  const iri = `<http://csrc.nist.gov/ns/oscal/poam#Item-${id}>`;
  if (!poamItemPredicateMap.hasOwnProperty(field)) return null;
  const predicate = poamItemPredicateMap[field].predicate;
  let statements;
  if (Array.isArray(itemIris)) {
    statements = itemIris
      .map((itemIri) => `${iri} ${predicate} ${itemIri}`)
      .join(".\n        ")
    }
  else {
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
