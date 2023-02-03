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
    case 'INFORMATION-TYPE-ENTRY':
      return informationTypeEntryReducer;
    case 'IMPACT-DEFINITION':
      return impactDefinitionReducer;
    default:
      throw new CyioError(`Unsupported reducer type ' ${type}'`)
  }
}
  
//
// Reducers
//
const informationTypeEntryReducer = (item) => {
  // if no object type was returned, compute the type from the IRI
  if (item.object_type === undefined) {
      if (item.entity_type !== undefined) item.object_type = item.entity_type;
      if (item.iri.includes('information-type-entry')) item.object_type = 'information-type-entry';
  }

  return {
      iri: item.iri,
      id: item.id,
      ...(item.object_type && { entity_type: item.object_type }),
      ...(item.created && { created: item.created }),
      ...(item.modified && { modified: item.modified }),
      ...(item.system && { system: item.system }),
      ...(item.identifier && { identifier: item.identifier }),
      ...(item.category && { category: item.category }),
      ...(item.title && { title: item.title }),
      ...(item.description && { description: item.description }),
      // hints for field-level resolver queries
      ...(item.confidentiality_impact && { confidentiality_impact_iri: item.confidentiality_impact }),
      ...(item.integrity_impact && { integrity_impact_iri: item.integrity_impact }),
      ...(item.availability_impact && { availability_impact_iri: item.availability_impact }),
  }
};

const impactDefinitionReducer = (item) => {
  // if no object type was returned, compute the type from the IRI
  if (item.object_type === undefined) {
      if (item.entity_type !== undefined) item.object_type = item.entity_type;
      if (item.iri.includes('impact-definition')) item.object_type = 'impact-definition';
  }

  return {
      iri: item.iri,
      id: item.id,
      ...(item.object_type && { entity_type: item.object_type }),
      ...(item.base_score !== undefined &&  { base_score: item.base_score }),
      ...(item.explanation &&  { explanation: item.explanation }),
      ...(item.recommendation &&  { recommendation: item.recommendation }),
  }
};
  
  // Query Builders - Information Type Entry
export const insertInformationTypeEntryQuery = (propValues) => {
  const id_material = {
    ...(propValues.identifier && {"identifier": propValues.identifier}),
    ...(propValues.system && {"system": propValues.system}),
  } ;
  const id = generateId( id_material, DARKLIGHT_NS );
  const timestamp = new Date().toISOString();

  // determine the appropriate ontology class type
  const iri = `<http://cyio.darklight.ai/information-type-entry--${id}>`;
  const insertPredicates = [];
  Object.entries(propValues).forEach((propPair) => {
    if (informationTypeEntryPredicateMap.hasOwnProperty(propPair[0])) {
      if (Array.isArray(propPair[1])) {
        for (let value of propPair[1]) {
          insertPredicates.push(informationTypeEntryPredicateMap[propPair[0]].binding(iri, value));
        }  
      } else {
        insertPredicates.push(informationTypeEntryPredicateMap[propPair[0]].binding(iri, propPair[1]));
      }
    }
  });

  const query = `
  INSERT DATA {
    GRAPH ${iri} {
      ${iri} a <http://nist.gov/ns/sp800-60#InformationTypeEntry> .
      ${iri} a <http://darklight.ai/ns/common#Object> .
      ${iri} <http://darklight.ai/ns/common#id> "${id}" .
      ${iri} <http://darklight.ai/ns/common#object_type> "information-type-entry" . 
      ${iri} <http://darklight.ai/ns/common#created> "${timestamp}"^^xsd:dateTime . 
      ${iri} <http://darklight.ai/ns/common#modified> "${timestamp}"^^xsd:dateTime . 
      ${insertPredicates.join(" . \n")}
    }
  }
  `;
  return {iri, id, query}
}
  
export const selectInformationTypeEntryQuery = (id, select) => {
  return selectInformationTypeEntryByIriQuery(`http://cyio.darklight.ai/information-type-entry--${id}`, select);
}

export const selectInformationTypeEntryByIriQuery = (iri, select) => {
  if (!iri.startsWith('<')) iri = `<${iri}>`;
  if (select === undefined || select === null) select = Object.keys(informationTypeEntryPredicateMap);

  // this is needed to assist in the determination of the type of the data source
  if (!select.includes('id')) select.push('id');
  if (!select.includes('object_type')) select.push('object_type');
  if (!select.includes('type')) select.push('type');

  const { selectionClause, predicates } = buildSelectVariables(informationTypeEntryPredicateMap, select);
  return `
  SELECT ?iri ${selectionClause}
  FROM <tag:stardog:api:context:local>
  WHERE {
    BIND(${iri} AS ?iri)
    ?iri a <http://nist.gov/ns/sp800-60#InformationTypeEntry> .
    ${predicates}
  }`
}

export const selectAllInformationTypeEntriesQuery = (select, args, parent) => {
  let constraintClause = '';
  if (select === undefined || select === null) select = Object.keys(informationTypeEntryPredicateMap);
  if (!select.includes('id')) select.push('id');
  if (!select.includes('object_type')) select.push('object_type');
  if (!select.includes('type')) select.push('type');

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

  const { selectionClause, predicates } = buildSelectVariables(informationTypeEntryPredicateMap, select);

  return `
  SELECT DISTINCT ?iri ${selectionClause} 
  FROM <tag:stardog:api:context:local>
  WHERE {
    ?iri a <http://nist.gov/ns/sp800-60#InformationTypeEntry> . 
    ${predicates}
    ${constraintClause}
  }
  `
}

export const deleteInformationTypeEntryQuery = (id) => {
  const iri = `http://cyio.darklight.ai/information-type-entry--${id}`;
  return deleteInformationTypeEntryByIriQuery(iri);
}

export const deleteInformationTypeEntryByIriQuery = (iri) => {
  if (!iri.startsWith('<')) iri = `<${iri}>`;
  return `
  DELETE {
    GRAPH ${iri} {
      ?iri ?p ?o
    }
  } WHERE {
    GRAPH ${iri} {
      ?iri a <http://nist.gov/ns/sp800-60#InformationTypeEntry> .
      ?iri ?p ?o
    }
  }
  `
}

export const deleteMultipleInformationTypeEntriesQuery = (ids) =>{
  const values = ids ? (ids.map((id) => `"${id}"`).join(' ')) : "";
  return `
  DELETE {
    GRAPH ?g {
      ?iri ?p ?o
    }
  } WHERE {
    GRAPH ?g {
      ?iri a <http://nist.gov/ns/sp800-60#InformationTypeEntry> .
      ?iri <http://darklight.ai/ns/common#id> ?id .
      ?iri ?p ?o .
      VALUES ?id {${values}}
    }
  }
  `
}

export const attachToInformationTypeEntryQuery = (id, field, itemIris) => {
  const iri = `<http://cyio.darklight.ai/information-type-entry--${id}>`;
  if (!informationTypeEntryPredicateMap.hasOwnProperty(field)) return null;
  const predicate = informationTypeEntryPredicateMap[field].predicate;
  let statements;
  if (Array.isArray(itemIris)) {
    statements = itemIris
      .map((itemIri) => `${iri} ${predicate} ${itemIri}`)
      .join(".\n        ")
    }
  else {
    if (!itemIris.startsWith('<')) itemIris = `<${itemIris}>`;
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

export const detachFromInformationTypeEntryQuery = (id, field, itemIris) => {
  const iri = `<http://cyio.darklight.ai/information-type-entry--${id}>`;
  if (!informationTypeEntryPredicateMap.hasOwnProperty(field)) return null;
  const predicate = informationTypeEntryPredicateMap[field].predicate;
  let statements;
  if (Array.isArray(itemIris)) {
    statements = itemIris
      .map((itemIri) => `${iri} ${predicate} ${itemIri}`)
      .join(".\n        ")
    }
  else {
    if (!itemIris.startsWith('<')) itemIris = `<${itemIris}>`;
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


// Query Builders - Impact Definition
export const insertImpactDefinitionQuery = (propValues) => {
  const id = generateId( );
  const timestamp = new Date().toISOString();

  // determine the appropriate ontology class type
  const iri = `<http://cyio.darklight.ai/impact-definition--${id}>`;
  const insertPredicates = [];
  Object.entries(propValues).forEach((propPair) => {
    if (impactDefinitionPredicateMap.hasOwnProperty(propPair[0])) {
      if (Array.isArray(propPair[1])) {
        for (let value of propPair[1]) {
          insertPredicates.push(impactDefinitionPredicateMap[propPair[0]].binding(iri, value));
        }  
      } else {
        insertPredicates.push(impactDefinitionPredicateMap[propPair[0]].binding(iri, propPair[1]));
      }
    }
  });

  const query = `
  INSERT DATA {
    GRAPH ${iri} {
      ${iri} a <http://nist.gov/ns/sp800-60#ImpactDefinition> .
      ${iri} a <http://darklight.ai/ns/common#ComplexDatatype> .
      ${iri} <http://darklight.ai/ns/common#id> "${id}" .
      ${iri} <http://darklight.ai/ns/common#object_type> "impact-definition" . 
      ${insertPredicates.join(" . \n")}
    }
  }
  `;
  return {iri, id, query}
}
  
export const selectImpactDefinitionQuery = (id, select) => {
  return selectInformationTypeEntryByIriQuery(`http://cyio.darklight.ai/impact-definition--${id}`, select);
}

export const selectImpactDefinitionByIriQuery = (iri, select) => {
  if (!iri.startsWith('<')) iri = `<${iri}>`;
  if (select === undefined || select === null) select = Object.keys(impactDefinitionPredicateMap);

  // this is needed to assist in the determination of the type of the object
  if (!select.includes('id')) select.push('id');
  if (!select.includes('object_type')) select.push('object_type');
  if (!select.includes('type')) select.push('type');

  const { selectionClause, predicates } = buildSelectVariables(impactDefinitionPredicateMap, select);
  return `
  SELECT ?iri ${selectionClause}
  FROM <tag:stardog:api:context:local>
  WHERE {
    BIND(${iri} AS ?iri)
    ?iri a <http://nist.gov/ns/sp800-60#ImpactDefinition> .
    ${predicates}
  }`
}

export const selectAllImpactDefinitionsQuery = (select, args, parent) => {
  let constraintClause = '';
  if (select === undefined || select === null) select = Object.keys(impactDefinitionPredicateMap);
  if (!select.includes('id')) select.push('id');
  if (!select.includes('object_type')) select.push('object_type');
  if (!select.includes('type')) select.push('type');

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

  const { selectionClause, predicates } = buildSelectVariables(impactDefinitionPredicateMap, select);

  return `
  SELECT DISTINCT ?iri ${selectionClause} 
  FROM <tag:stardog:api:context:local>
  WHERE {
    ?iri a <http://nist.gov/ns/sp800-60#ImpactDefintion> . 
    ${predicates}
    ${constraintClause}
  }
  `
}

export const deleteImpactDefinitionQuery = (id) => {
  const iri = `http://cyio.darklight.ai/impact-definition--${id}`;
  return deleteImpactDefinitionByIriQuery(iri);
}

export const deleteImpactDefinitionByIriQuery = (iri) => {
  if (!iri.startsWith('<')) iri = `<${iri}>`;
  return `
  DELETE {
    GRAPH ${iri} {
      ?iri ?p ?o
    }
  } WHERE {
    GRAPH ${iri} {
      ?iri a <http://nist.gov/ns/sp800-60#ImpactDefinition> .
      ?iri ?p ?o
    }
  }
  `
}


// Predicate Maps
export const informationTypeEntryPredicateMap = {
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
  system: {
    predicate: "<http://nist.gov/ns/sp800-60#system>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:anyURI` : null,  this.predicate, "system");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  identifier: {
    predicate: "<http://nist.gov/ns/sp800-60#title>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "identifier");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  category: {
    predicate: "<http://nist.gov/ns/sp800-60#category>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "category");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  title: {
    predicate: "<http://nist.gov/ns/sp800-60#title>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "title");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  confidentiality_impact: {
    predicate: "<http://nist.gov/ns/sp800-60#confidentiality_impact>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"@en-US` : null,  this.predicate, "confidentiality_impact");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  integrity_impact: {
    predicate: "<http://nist.gov/ns/sp800-60#integrity_impact>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"@en-US` : null,  this.predicate, "integrity_impact");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  availability_impact: {
    predicate: "<http://nist.gov/ns/sp800-60#availability_impact>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"@en-US` : null,  this.predicate, "availability_impact");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  catalog: {
    predicate: "^<http://nist.gov/ns/sp800-60#entries>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"@en-US` : null,  this.predicate, "catalog");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
};

export const impactDefinitionPredicateMap = {
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
  explanation: {
    predicate: "<http://nist.gov/ns/sp800-60#explanation>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"@en-US`: null, this.predicate, "explanation");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  recommendation: {
    predicate: "<http://nist.gov/ns/sp800-60#recommendation>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"@en-US`: null, this.predicate, "recommendation");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
};

// Serialization schema
export const singularizeInformationTypeEntrySchema = { 
  singularizeVariables: {
    "": false, // so there is an object as the root instead of an array
    "id": true,
    "iri": true,
    "object_type": true,
    "entity_type": true,
    "created": true,
    "modified": true,
    "system": true,
    "identifier": true,
    "category": true,
    "title": true,
    "description": true,
    "confidentiality_impact": true,
    "integrity_impact": true,
    "availability_impact": true,
  }
};

export const singularizeImpactDefinitionSchema = { 
  singularizeVariables: {
    "": false, // so there is an object as the root instead of an array
    "id": true,
    "iri": true,
    "object_type": true,
    "entity_type": true,
    "base_score": true,
    "explanation": true,
    "recommendation": true,
  }
};
