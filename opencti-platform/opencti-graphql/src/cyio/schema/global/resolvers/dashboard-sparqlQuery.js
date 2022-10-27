import { match } from 'ramda';
import {CyioError, optionalizePredicate, parameterizePredicate, buildSelectVariables} from '../../utils.js';
import {objectMap} from '../global-utils.js'

// Reducer Selection
export function getReducer( type ) {
  switch( type ) {
    case 'ENTITY':
      return entitiesReducer;
    default:
      throw new Error(`Unsupported reducer type ' ${type}'`)
  }
}

//
// Reducers
//
const entitiesReducer = (item) => {
  // if no object type was returned, compute the type from the IRI
  if ( item.object_type === undefined ) {
    if (item.iri.includes('Software')) item.object_type = 'software';
    if (item.iri.includes('Hardware')) item.object_type = 'hardware';
  }

  return {
    iri: item.iri,
    id: item.id,
    ...(item.object_type && {"entity_type": item.object_type}),
    ...(item.created && {created: item.created}),
    ...(item.modified && {modified: item.modified}),
  }
}

export const entitiesCountQuery = (args) => {
  let classIri, predicate, filterClause, type, field, endDate;
  const matchPredicates = [];
  if ('type' in args) {
    type = args.type.toLowerCase();
    field = 'object_type';
  } else if (args.field === 'entity_type') {
    field = 'object_type';
    for (let match of args.match) {
      match = match.toLowerCase();
      type = match;
      if (!objectMap.hasOwnProperty(match)) {
        let found = false;
        for (let [key, value] of Object.entries(objectMap)) {
          // check for alternate key
          if (value.alternateKey != undefined && match == value.alternateKey) {
            type = key;
            found = true;
            break;
          }
          // check if the GraphQL type name was supplied
          if (match == value.graphQLType) {
            type = key;
            found = true;
            break;
          }
        }
        if (!found) throw new CyioError(`Unknown field '${args.match}'`);
      }
    }
  }
  if (type === undefined) throw new CyioError (`Unable to determine object type`);

  // Validate field is defined 
  const predicateMap = objectMap[type].predicateMap;
  if ('field' in args && args.field !== 'entity_type') {
    field = args.field;
    if (!predicateMap.hasOwnProperty(field)) throw new CyioError(`Field '${field}' is not defined for the entity.`);
    predicate = predicateMap[args.field].predicate;
  }

  while (objectMap[type].parent !== undefined) {
    type = objectMap[type].parent;
  }

  // construct the IRI
  classIri = `<${objectMap[type].iriTemplate}>`;

  if (('endDate' in args) && (args.endDate instanceof Date)) {
    // convert end date to string, if specified 
    endDate = args.endDate.toISOString();
  } else{
    // uses the current date and time
    endDate = new Date().toISOString();
  }
  filterClause = `
    ?iri <http://darklight.ai/ns/common#modified> ?created .
    FILTER (?created > "${endDate}"^^xsd:dateTime)
    `;

  if (args.field !== 'entity_type') {
    if ('match' in args && args.match.length > 0) {
      let values = "";
      for (let match of args.match) {
        values = values + ` "${match}"`;
      }
      if (values.length > 0) {
        values = values.trim();
        matchPredicates.push(`  Values ?o {${values}} .`);
        matchPredicates.push(`  ?iri ${predicate} ?o .`);    
      }
    }
  }
  
  return `
  PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>
  SELECT DISTINCT (COUNT(?iri) AS ?total) ?count
  FROM <tag:stardog:api:context:local>
  WHERE {
    ?iri a ${classIri} .
    OPTIONAL {
      {
        SELECT (COUNT(?created) AS ?count)
        WHERE {
          ?iri a ${classIri} .
          ${matchPredicates.join("\n")}
          ${filterClause}
        }
      }
    }
  } GROUP BY ?count
  `;
}

export const entitiesTimeSeriesQuery = (args) => {
  let classIri, predicate, type, field, startDate, endDate;
  const matchPredicates = [];
  if ('type' in args) {
    type = args.type.toLowerCase();
    field = 'object_type';
  } else if (args.field === 'entity_type') {
    field = 'object_type';
    for (let match of args.match) {
      match = match.toLowerCase();
      type = match;
      if (!objectMap.hasOwnProperty(match)) {
        let found = false;
        for (let [key, value] of Object.entries(objectMap)) {
          // check for alternate key
          if (value.alternateKey != undefined && match == value.alternateKey) {
            type = key;
            found = true;
            break;
          }
          // check if the GraphQL type name was supplied
          if (match == value.graphQLType) {
            type = key;
            found = true;
            break;
          }
        }
        if (!found) throw new CyioError(`Unknown field '${args.match}'`);
      }
    }
  }
  if (type === undefined) throw new CyioError (`Unable to determine object type`);

  // Validate field is defined 
  const predicateMap = objectMap[type].predicateMap;
  if ('field' in args && args.field !== 'entity_type') {
    field = args.field;
    if (!predicateMap.hasOwnProperty(field)) throw new CyioError(`Field '${field}' is not defined for the entity.`);
    predicate = predicateMap[args.field].predicate;
  }

  while (objectMap[type].parent !== undefined) {
    type = objectMap[type].parent;
  }

  // construct the IRI
  if ('objectId' in args) {
    classIri = `<${objectMap[type].iriTemplate}-${args.objectId}>`;
  } else {
    classIri = `<${objectMap[type].iriTemplate}>`;
  }

  if (('startDate' in args) && (args.startDate instanceof Date)) {
    // convert start date to string, if specified 
    startDate = args.startDate.toISOString();
  } else {
    // use Epoch time
    startDate = '1970-01-01-01T00:00:00Z';
  }
  if (('endDate' in args) && (args.endDate instanceof Date)) {
    // convert end date to string, if specified 
    endDate = args.endDate.toISOString();
  } else{
    // uses the current date and time
    endDate = new Date().toISOString();
  }

  if (args.field !== 'entity_type') {
    if ('match' in args && args.match.length > 0) {
      let values = "";
      for (let match of args.match) {
        values = values + ` "${match}"`;
      }
      if (values.length > 0) {
        values = values.trim();
        matchPredicates.push(`  Values ?o {${values}} .`);
        matchPredicates.push(`  ?iri ${predicate} ?o .`);    
      }
    }
  }
  
  return `
  PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>
  SELECT ?iri ?created
  FROM <tag:stardog:api:context:local>
  WHERE {
    ?iri a ${classIri} .
    ${matchPredicates.join("\n")}
    ?iri <http://darklight.ai/ns/common#created> ?created .
    FILTER (?created > "${startDate}"^^xsd:dateTime && ?created < "${endDate}"^^xsd:dateTime)
  } GROUP BY ?iri ?created
  `;
}

export const entitiesDistributionQuery = (args) => {
  let classIri, predicate, selectionClause, type, field, startDate, endDate, limitClause = "";
  const matchPredicates = [];
  if ('type' in args) {
    type = args.type.toLowerCase();
    field = 'object_type';
  } else if (args.field === 'entity_type') {
    field = 'object_type';
    for (let match of args.match) {
      match = match.toLowerCase();
      type = match;
      if (!objectMap.hasOwnProperty(match)) {
        let found = false;
        for (let [key, value] of Object.entries(objectMap)) {
          // check for alternate key
          if (value.alternateKey != undefined && match == value.alternateKey) {
            type = key;
            found = true;
            break;
          }
          // check if the GraphQL type name was supplied
          if (match == value.graphQLType) {
            type = key;
            found = true;
            break;
          }
        }
        if (!found) throw new CyioError(`Unknown field '${args.match}'`);
      }
    }
  }
  if (type === undefined) throw new CyioError (`Unable to determine object type`);

  // Validate field is defined 
  const predicateMap = objectMap[type].predicateMap;
  if ('field' in args && args.field !== 'entity_type') {
    field = args.field;
    if (!predicateMap.hasOwnProperty(field)) throw new CyioError(`Field '${field}' is not defined for the entity.`);
    predicate = predicateMap[args.field].predicate;
    }

  while (objectMap[type].parent !== undefined) {
    type = objectMap[type].parent;
  }

  // construct the IRI
  if ('objectId' in args) {
    classIri = `<${objectMap[type].iriTemplate}-${args.objectId}>`;
  } else {
    classIri = `<${objectMap[type].iriTemplate}>`;
  }

  // build filter for start and end dates
  if (('startDate' in args) && (args.startDate instanceof Date)) {
    // convert start date to string, if specified 
    startDate = args.startDate.toISOString();
  } else {
    // use Epoch time
    startDate = '1970-01-01-01T00:00:00Z';
  }
  if (('endDate' in args) && (args.endDate instanceof Date)) {
    // convert end date to string, if specified 
    endDate = args.endDate.toISOString();
  } else{
    // uses the current date and time
    endDate = new Date().toISOString();
  }

  // Build values clause to match only those items specified
  if (args.field !== 'entity_type') {
    selectionClause = `?${args.field}`;
    if ('match' in args && args.match.length > 0) {
      let values = "";
      for (let match of args.match) {
        values = values + ` "${match}"`;
      }
      if (values.length > 0) {
        values = values.trim();
        matchPredicates.push(`  Values ?o {${values}} .`);
        matchPredicates.push(`  ?iri ${predicate} ?o .`);    
      }
    }
  }

  // build limit clause
  if ('limit' in args) {
    limitClause = `LIMIT ${args.limit}`
  }
  
  return `
  PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>
  SELECT ?iri ?created ?o
  FROM <tag:stardog:api:context:local>
  WHERE {
    ?iri a ${classIri} .
    ${matchPredicates.join("\n")}
    ?iri <http://darklight.ai/ns/common#created> ?created .
    FILTER (?created > "${startDate}"^^xsd:dateTime && ?created < "${endDate}"^^xsd:dateTime)
  } GROUP BY ?iri ?created ?o ${limitClause}
  `;
}

// Predicate Map
export const entityPredicateMap = {
  id: {
    predicate: "<http://docs.oasis-open.org/ns/cti#id>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "id");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
  },
  object_type: {
    predicate: "<http://docs.oasis-open.org/ns/cti#object_type>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "object_type");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  created: {
    predicate: "<http://docs.oasis-open.org/ns/cti#created>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime` : null,  this.predicate, "created");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  modified: {
    predicate: "<http://docs.oasis-open.org/ns/cti#modified>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime` : null,  this.predicate, "modified");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
}

// Singularization Schema
export const dashboardSingularizeSchema = { singularizeVariables: {
    "": false, // so there is an object as the root instead of an array
    "id": true,
    "iri": true,
    "object_type": true,
    "o": true,
    "total": true,
    "count": true,
    "created": true,
    "modified": true,
    "name": true,
    "risk_status": true,
    "deadline": true,
    "accepted": true,
    "false_positive": true,
    "priority": true,
    "vendor_dependency": true,
    "remediation_type": true,
    "remediation_lifecycle": true,
  }
};

