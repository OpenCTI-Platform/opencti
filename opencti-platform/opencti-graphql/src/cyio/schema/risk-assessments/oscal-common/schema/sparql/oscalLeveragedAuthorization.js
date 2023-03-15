import { UserInputError } from 'apollo-server-errors';
import { 
  optionalizePredicate, 
  parameterizePredicate, 
  buildSelectVariables, 
  attachQuery,
  detachQuery,
  generateId, 
  DARKLIGHT_NS,
} from '../../../../utils.js';
  
// Reducer Selection
export function getReducer(type) {
  switch (type) {
    case 'OSCAL-LEVERAGED-AUTHORIZATION':
      return oscalLeveragedAuthorizationReducer;
    default:
      throw new UserInputError(`Unsupported reducer type ' ${type}'`)
  }
}

//
// Reducers
//
const oscalLeveragedAuthorizationReducer = (item) => {
  // if no object type was returned, compute the type from the IRI
  if (item.object_type === undefined) {
    if (item.entity_type !== undefined) item.object_type = item.entity_type;
    if (item.iri.includes('oscal-leveraged-authorization')) item.object_type = 'oscal-leveraged-authorization';
  }

  return {
    iri: item.iri,
    id: item.id,
    ...(item.object_type && { entity_type: item.object_type }),
    ...(item.created && { created: item.created }),
    ...(item.modified && { modified: item.modified }),
    ...(item.title && { title: item.title }),
    ...(item.date_authorized && { date_authorized: item.date_authorized }),
    // hints for field-level resolver queries
    ...(item.party && { party_iri: item.party }),
    // hints for general lists of items
    ...(item.labels && { label_iris: item.labels }),
    ...(item.links && { link_iris: item.links }),
    ...(item.remarks && { remark_iris: item.remarks }),
  }
};

//
// Query Builders
//
export const selectOscalLeveragedAuthorizationQuery = (id, select) => {
  return selectOscalLeveragedAuthorizationByIriQuery(`http://cyio.darklight.ai/oscal-leveraged-authorization${id}`, select);
}

export const selectOscalLeveragedAuthorizationByIriQuery = (iri, select) => {
  if (!iri.startsWith('<')) iri = `<${iri}>`;
  if (select === undefined || select === null) select = Object.keys(oscalLeveragedAuthorizationPredicateMap);

  // this is needed to assist in the determination of the type of the data source
  if (!select.includes('id')) select.push('id');
  if (!select.includes('object_type')) select.push('object_type');

  const { selectionClause, predicates } = buildSelectVariables(oscalLeveragedAuthorizationPredicateMap, select);
  return `
  SELECT ?iri ${selectionClause}
  FROM <tag:stardog:api:context:local>
  WHERE {
    BIND(${iri} AS ?iri)
    ?iri a <http://csrc.nist.gov/ns/oscal/common#LeveragedAuthorization> .
    ${predicates}
  }`
}

export const selectAllOscalLeveragedAuthorizationsQuery = (select, args, parent) => {
  let constraintClause = '';
  if (select === undefined || select === null) select = Object.keys(oscalLeveragedAuthorizationPredicateMap);
  if (!select.includes('id')) select.push('id');
  if (!select.includes('object_type')) select.push('object_type');

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

  // build lists of selection variables and predicates
  const { selectionClause, predicates } = buildSelectVariables(oscalLeveragedAuthorizationPredicateMap, select);

  return `
  SELECT DISTINCT ?iri ${selectionClause} 
  FROM <tag:stardog:api:context:local>
  WHERE {
    ?iri a <http://csrc.nist.gov/ns/oscal/common#LeveragedAuthorization> . 
    ${predicates}
    ${constraintClause}
  }
  `
}

export const insertOscalLeveragedAuthorizationQuery = (propValues) => {
  const id_material = {
    ...(propValues.name && {"name": propValues.name}),
  } ;
  const id = generateId( id_material, DARKLIGHT_NS );
  const timestamp = new Date().toISOString();

  // determine the appropriate ontology class type
  const iri = `<http://cyio.darklight.ai/oscal-leveraged-authorization${id}>`;
  const insertPredicates = [];
  Object.entries(propValues).forEach((propPair) => {
    if (oscalLeveragedAuthorizationPredicateMap.hasOwnProperty(propPair[0])) {
      if (Array.isArray(propPair[1])) {
        for (let value of propPair[1]) {
          insertPredicates.push(oscalLeveragedAuthorizationPredicateMap[propPair[0]].binding(iri, value));
        }  
      } else {
        insertPredicates.push(oscalLeveragedAuthorizationPredicateMap[propPair[0]].binding(iri, propPair[1]));
      }
    }
  });

  const query = `
  INSERT DATA {
    GRAPH ${iri} {
      ${iri} a <http://csrc.nist.gov/ns/oscal/common#LeveragedAuthorization> .
      ${iri} a <http://csrc.nist.gov/ns/oscal/common#Object> .
      ${iri} a <http://darklight.ai/ns/common#Object> .
      ${iri} <http://darklight.ai/ns/common#id> "${id}" .
      ${iri} <http://darklight.ai/ns/common#object_type> "oscal-leveraged-authorization" . 
      ${iri} <http://darklight.ai/ns/common#created> "${timestamp}"^^xsd:dateTime . 
      ${iri} <http://darklight.ai/ns/common#modified> "${timestamp}"^^xsd:dateTime . 
      ${insertPredicates.join(" . \n")}
    }
  }
  `;
  return {iri, id, query}
}
    
export const deleteOscalLeveragedAuthorizationQuery = (id) => {
  const iri = `http://cyio.darklight.ai/oscal-leveraged-authorization${id}`;
  return deleteOscalLeveragedAuthorizationByIriQuery(iri);
}

export const deleteOscalLeveragedAuthorizationByIriQuery = (iri) => {
  if (!iri.startsWith('<')) iri = `<${iri}>`;
  return `
  DELETE {
    GRAPH ${iri} {
      ?iri ?p ?o
    }
  } WHERE {
    GRAPH ${iri} {
      ?iri a <http://csrc.nist.gov/ns/oscal/common#LeveragedAuthorization> .
      ?iri ?p ?o
    }
  }
  `
}

export const deleteMultipleOscalLeveragedAuthorizationsQuery = (ids) =>{
  const values = ids ? (ids.map((id) => `"${id}"`).join(' ')) : "";
  return `
  DELETE {
    GRAPH ?g {
      ?iri ?p ?o
    }
  } WHERE {
    GRAPH ?g {
      ?iri a <http://csrc.nist.gov/ns/oscal/common#LeveragedAuthorization> .
      ?iri <http://darklight.ai/ns/common#id> ?id .
      ?iri ?p ?o .
      VALUES ?id {${values}}
    }
  }
  `
}

export const attachToOscalLeveragedAuthorizationQuery = (id, field, itemIris) => {
  if (!oscalLeveragedAuthorizationPredicateMap.hasOwnProperty(field)) return null;
  const iri = `<http://cyio.darklight.ai/oscal-leveraged-authorization${id}>`;
  const predicate = oscalLeveragedAuthorizationPredicateMap[field].predicate;

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
    oscalLeveragedAuthorizationPredicateMap, 
    '<http://csrc.nist.gov/ns/oscal/common#LeveragedAuthorization>'
  );
}

export const detachFromOscalLeveragedAuthorizationQuery = (id, field, itemIris) => {
  if (!oscalLeveragedAuthorizationPredicateMap.hasOwnProperty(field)) return null;
  const iri = `<http://cyio.darklight.ai/oscal-leveraged-authorization${id}>`;
  const predicate = oscalLeveragedAuthorizationPredicateMap[field].predicate;

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
    oscalLeveragedAuthorizationPredicateMap, 
    '<http://csrc.nist.gov/ns/oscal/common#LeveragedAuthorization>'
  );
}

//
// Predicate Maps
//
export const oscalLeveragedAuthorizationPredicateMap = {
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
  title: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#title>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "title");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  party: {
    predicate: "<http://darklight.ai/ns/common#party>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "party");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  date_authorized: {
    predicate: "<http://darklight.ai/ns/common#date_authorized>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:date` : null,  this.predicate, "date_authorized");},
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
};

//
// Serialization schema
//
export const singularizeOscalLeveragedAuthorizationSchema = { 
  singularizeVariables: {
    "": false, // so there is an object as the root instead of an array
    "id": true,
    "iri": true,
    "object_type": true,
    "entity_type": true,
    "created": true,
    "modified": true,
    "title": true,
    "party": true,
    "data_authorized": true,
  }
};
