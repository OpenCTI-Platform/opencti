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
    case 'CONNECTION-INFORMATION':
      return connectionInformationReducer;
    case 'CONNECTION-HEADER':
      return connectionHeaderReducer;
    default:
      throw new CyioError(`Unsupported reducer type ' ${type}'`)
  }
}

//
// Reducers
//
const connectionInformationReducer = (item) => {
  // if no object type was returned, compute the type from the IRI
  if (item.object_type === undefined) {
    if (item.entity_type !== undefined) item.object_type = item.entity_type;
    if (item.iri.includes('connection-information')) item.object_type = 'connection-information';
  }

  return {
    iri: item.iri,
    id: item.id,
    ...(item.object_type && { entity_type: item.object_type }),
    ...(item.created && { created: item.created }),
    ...(item.modified && { modified: item.modified }),
    ...(item.name && { name: item.name }),
    ...(item.display_name && { display_name: item.display_name }),
    ...(item.description && { description: item.description }),
    ...(item.connector_type && {connector_type: item.connector_type}),
    ...(item.secure !== undefined && { secure: item.secure }),
    ...(item.host && { host: item.host }),
    ...(item.port && { port: item.port }),
    ...(item.query && { query: item.query }),
    ...(item.query_initial && {query_initial: item.query_initial}),
    ...(item.query_index_field && { query_index_field: item.query_index_field }),
    ...(item.query_sleep_interval && { query_sleep_interval: item.query_sleep_interval }),
    ...(item.ca && { ca: item.ca }),
    ...(item.http_request_method && { http_request_method: item.http_request_method }),
    ...(item.headers && { headers: item.headers }),
    ...(item.api_key && { api_key: item.api_key }),
    ...(item.username && { username: item.username }),
    ...(item.passphrase && { passphrase: item.passphrase }),
    ...(item.listen && { listen: item.listen }),
    ...(item.listen_exchange && { listen_exchange: item.listen_exchange }),
    ...(item.push && { push: item.push }),
    ...(item.push_exchange && { push_exchange: item.push_exchange }),
  }
}


// Query Builders
export const insertConnectionInformationQuery = (propValues) => {
  const id_material = {
    ...(propValues.connector_type && {"connector_type": propValues.connector_type}),
    ...(propValues.name && {"name": propValues.name}),
  } ;
  const id = generateId( id_material, DARKLIGHT_NS );
  // const id = generateId( );
  const timestamp = new Date().toISOString();

  // determine the appropriate ontology class type
  const iri = `<http://cyio.darklight.ai/connection-information--${id}>`;
  const insertPredicates = [];
  Object.entries(propValues).forEach((propPair) => {
    if (connectionInformationPredicateMap.hasOwnProperty(propPair[0])) {
      if (Array.isArray(propPair[1])) {
        for (let value of propPair[1]) {
          insertPredicates.push(connectionInformationPredicateMap[propPair[0]].binding(iri, value));
        }
      } else {
        insertPredicates.push(connectionInformationPredicateMap[propPair[0]].binding(iri, propPair[1]));
      }
    }
  });

  const query = `
    INSERT DATA {
      GRAPH ${iri} {
        ${iri} a <http://darklight.ai/ns/cyio/connection#ConnectionInformation> .
        ${iri} a <http://darklight.ai/ns/common#Object> .
        ${iri} <http://darklight.ai/ns/common#id> "${id}" .
        ${iri} <http://darklight.ai/ns/common#object_type> "connection-information" . 
        ${iri} <http://darklight.ai/ns/common#created> "${timestamp}"^^xsd:dateTime . 
        ${iri} <http://darklight.ai/ns/common#modified> "${timestamp}"^^xsd:dateTime . 
        ${insertPredicates.join(" . \n")}
      }
    }
    `;
  return { iri, id, query }
}

export const selectConnectionInformationQuery = (id, select) => {
  return selectConnectionInformationByIriQuery(`http://cyio.darklight.ai/connection-information--${id}`, select);
}

export const selectConnectionInformationByIriQuery = (iri, select) => {
  if (!iri.startsWith('<')) iri = `<${iri}>`;
  if (select === undefined || select === null) select = Object.keys(connectionInformationPredicateMap);

  // this is needed to assist in the determination of the type of the connection information
  if (!select.includes('id')) select.push('id');
  if (!select.includes('object_type')) select.push('object_type');

  const { selectionClause, predicates } = buildSelectVariables(connectionInformationPredicateMap, select);
  return `
  SELECT ?iri ${selectionClause}
  FROM <tag:stardog:api:context:local>
  WHERE {
    BIND(${iri} AS ?iri)
    ?iri a <http://darklight.ai/ns/cyio/connection#ConnectionInformation> .
    ${predicates}
  }`
}

export const selectAllConnectionInformationQuery = (select, args, parent) => {
  if (select === undefined || select === null) select = Object.keys(connectionInformationPredicateMap);
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

  const { selectionClause, predicates } = buildSelectVariables(connectionInformationPredicateMap, select);

  return `
  SELECT DISTINCT ?iri ${selectionClause} 
  FROM <tag:stardog:api:context:local>
  WHERE {
    ?iri a <http://darklight.ai/ns/cyio/connection#ConnectionInformation> . 
    ${predicates}
  }
  `
}

export const deleteConnectionInformationQuery = (id) => {
  const iri = `http://cyio.darklight.ai/connection-information--${id}`;
  return deleteConnectionInformationByIriQuery(iri);
}

export const deleteConnectionInformationByIriQuery = (iri) => {
  if (!iri.startsWith('<')) iri = `<${iri}>`;
  return `
  DELETE {
    GRAPH ${iri} {
      ?iri ?p ?o
    }
  } WHERE {
    GRAPH ${iri} {
      ?iri a <http://darklight.ai/ns/cyio/connection#ConnectionInformation> .
      ?iri ?p ?o
    }
  }
  `
}

export const deleteMultipleConnectionInformationQuery = (ids) =>{
  const values = ids ? (ids.map((id) => `"${id}"`).join(' ')) : "";
  return `
  DELETE {
    GRAPH ?g {
      ?iri ?p ?o
    }
  } WHERE {
    GRAPH ?g {
      ?iri a <http://darklight.ai/ns/cyio/connection#ConnectionInformation> .
      ?iri <http://darklight.ai/ns/common#id> ?id .
      ?iri ?p ?o .
      VALUES ?id {${values}}
    }
  }
  `
}

export const attachToConnectionInformationQuery = (id, field, itemIris) => {
  const iri = `<http://cyio.darklight.ai/connection-information--${id}>`;
  if (!connectionInformationPredicateMap.hasOwnProperty(field)) return null;
  const predicate = connectionInformationPredicateMap[field].predicate;
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

export const detachFromConnectionInformationQuery = (id, field, itemIris) => {
  const iri = `<http://cyio.darklight.ai/connection-information--${id}>`;
  if (!connectionInformationPredicateMap.hasOwnProperty(field)) return null;
  const predicate = connectionInformationPredicateMap[field].predicate;
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



// Predicate Maps
export const connectionInformationPredicateMap = {
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
    predicate: "<http://darklight.ai/ns/cyio/connection#name>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "name");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  description: {
    predicate: "<http://darklight.ai/ns/cyio/connection#description>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"@en-US` : null,  this.predicate, "description");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  connector_type: {
    predicate: "<http://darklight.ai/ns/cyio/connection#connector_type>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "connector_type");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  secure: {
    predicate: "<http://darklight.ai/ns/cyio/connection#secure>",
    binding: function (iri, value) { return parameterizePredicate(iri, value !== undefined ? `"${value}"^^xsd:boolean` : null,  this.predicate, "secure");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  host: {
    predicate: "<http://darklight.ai/ns/cyio/connection#host>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "host");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  port: {
    predicate: "<http://darklight.ai/ns/cyio/connection#port>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:positiveInteger` : null,  this.predicate, "port");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  query: {
    predicate: "<http://darklight.ai/ns/cyio/connection#query>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "query");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  query_initial: {
    predicate: "<http://darklight.ai/ns/cyio/connection#query_initial>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "query_initial");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  query_index_field: {
    predicate: "<http://darklight.ai/ns/cyio/connection#query_index_field>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "query_index_field");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  query_sleep_interval: {
    predicate: "<http://darklight.ai/ns/cyio/connection#query_sleep_interval>",
    binding: function (iri, value) { return parameterizePredicate(iri, value !== undefined ? `"${value}"^^xsd:positiveInteger` : null,  this.predicate, "query_sleep_interval");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  ca: {
    predicate: "<http://darklight.ai/ns/cyio/connection#ca>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "ca");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  headers: {
    predicate: "<http://darklight.ai/ns/cyio/connection#headers>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "headers");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  http_request_method: {
    predicate: "<http://darklight.ai/ns/cyio/connection#http_request_method>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "http_request_method");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  api_key: {
    predicate: "<http://darklight.ai/ns/cyio/connection#api_key>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "api_key");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  username: {
    predicate: "<http://darklight.ai/ns/cyio/connection#username>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "username");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  passphrase: {
    predicate: "<http://darklight.ai/ns/cyio/connection#passphrase>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "passphrase");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  listen: {
    predicate: "<http://darklight.ai/ns/cyio/connection#listen>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "listen");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  listen_exchange: {
    predicate: "<http://darklight.ai/ns/cyio/connection#listen_exchange>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "listen_exchange");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  push: {
    predicate: "<http://darklight.ai/ns/cyio/connection#push>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "push");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  push_exchange: {
    predicate: "<http://darklight.ai/ns/cyio/connection#push_exchange>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "push_exchange");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
}

export const singularizeSchema = { 
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
    "connector_type": true,
    "secure": true,
    "host": true,
    "port": true,
    "query": true,
    "query_initial": true,
    "query_index_field": true,
    "query_sleep_interval": true,
    "http_request_method": true,
    "api_key": true,
    "username": true,
    "passphrase": true,
    "listen": true,
    "listen_exchange": true,
    "push": true,
    "push_exchange": true,
  }
};
