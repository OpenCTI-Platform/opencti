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
    case 'OSCAL-USER':
      return oscalUserReducer;
    case 'AUTHORIZED-PRIVILEGE':
        return authorizedPrivilegeReducer;
    default:
      throw new UserInputError(`Unsupported reducer type ' ${type}'`)
  }
}
    
//
// Reducers
//
const oscalUserReducer = (item) => {
  // if no object type was returned, compute the type from the IRI
  if (item.object_type === undefined) {
    if (item.entity_type !== undefined) item.object_type = item.entity_type;
    if (item.iri.includes('oscal-user')) item.object_type = 'oscal-user';
  }

  return {
    iri: item.iri,
    id: item.id,
    ...(item.object_type && { entity_type: item.object_type }),
    ...(item.created && { created: item.created }),
    ...(item.modified && { modified: item.modified }),
    ...(item.user_type && { user_type: item.user_type }),
    ...(item.name && { name: item.name }),
    ...(item.short_name && { short_name: item.short_name }),
    ...(item.description && { description: item.description }),
    ...(item.privilege_level && { privilege_level: item.privilege_level }),
    // hints for field-level resolver queries
    ...(item.roles && { role_iris: item.roles }),
    ...(item.authorized_privileges && { authorized_privilege_iris: item.authorized_privileges }),
    // hints for general lists of items
    ...(item.labels && { label_iris: item.labels }),
    ...(item.links && { link_iris: item.links }),
    ...(item.remarks && { remark_iris: item.remarks }),
  }
};

const authorizedPrivilegeReducer = (item) => {
  // if no object type was returned, compute the type from the IRI
  if (item.object_type === undefined) {
    if (item.entity_type !== undefined) item.object_type = item.entity_type;
    if (item.iri.includes('authorized-privilege')) item.object_type = 'authorized-privilege';
  }

  return {
      iri: item.iri,
      id: item.id,
      ...(item.object_type && { entity_type: item.object_type }),
      ...(item.name && { name: item.name }),
      ...(item.description && { description: item.description }),
      ...(item.functions_performed && { functions_performed: item.functions_performed }),
  }
};

//
// Query Builders
//
export const selectOscalUserQuery = (id, select) => {
  return selectOscalUserByIriQuery(`http://cyio.darklight.ai/oscal-user--${id}`, select);
}

export const selectOscalUserByIriQuery = (iri, select) => {
  if (!iri.startsWith('<')) iri = `<${iri}>`;
  if (select === undefined || select === null) select = Object.keys(oscalUserPredicateMap);

  // this is needed to assist in the determination of the type of the data source
  if (!select.includes('id')) select.push('id');
  if (!select.includes('object_type')) select.push('object_type');

  const { selectionClause, predicates } = buildSelectVariables(oscalUserPredicateMap, select);
  return `
  SELECT ?iri ${selectionClause}
  FROM <tag:stardog:api:context:local>
  WHERE {
    BIND(${iri} AS ?iri)
    ?iri a <http://csrc.nist.gov/ns/oscal/common#OscalUser> .
    ${predicates}
  }`
}

export const selectAllOscalUsersQuery = (select, args, parent) => {
  let constraintClause = '';
  if (select === undefined || select === null) select = Object.keys(oscalUserPredicateMap);
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
  const { selectionClause, predicates } = buildSelectVariables(oscalUserPredicateMap, select);

  return `
  SELECT DISTINCT ?iri ${selectionClause} 
  FROM <tag:stardog:api:context:local>
  WHERE {
    ?iri a <http://csrc.nist.gov/ns/oscal/common#OscalUser> . 
    ${predicates}
    ${constraintClause}
  }
  `
}

export const insertOscalUserQuery = (propValues) => {
  const id_material = {
    ...(propValues.name && {"name": propValues.name}),
  } ;
  const id = generateId( id_material, DARKLIGHT_NS );
  const timestamp = new Date().toISOString();

  // determine the appropriate ontology class type
  const iri = `<http://cyio.darklight.ai/oscal-user--${id}>`;
  const insertPredicates = [];
  Object.entries(propValues).forEach((propPair) => {
    if (oscalUserPredicateMap.hasOwnProperty(propPair[0])) {
      if (Array.isArray(propPair[1])) {
        for (let value of propPair[1]) {
          insertPredicates.push(oscalUserPredicateMap[propPair[0]].binding(iri, value));
        }  
      } else {
        insertPredicates.push(oscalUserPredicateMap[propPair[0]].binding(iri, propPair[1]));
      }
    }
  });

  const query = `
  INSERT DATA {
    GRAPH ${iri} {
      ${iri} a <http://csrc.nist.gov/ns/oscal/common#OscalUser> .
      ${iri} a <http://csrc.nist.gov/ns/oscal/common#Object> .
      ${iri} a <http://darklight.ai/ns/common#Object> .
      ${iri} <http://darklight.ai/ns/common#id> "${id}" .
      ${iri} <http://darklight.ai/ns/common#object_type> "oscal-user" . 
      ${iri} <http://darklight.ai/ns/common#created> "${timestamp}"^^xsd:dateTime . 
      ${iri} <http://darklight.ai/ns/common#modified> "${timestamp}"^^xsd:dateTime . 
      ${insertPredicates.join(" . \n")}
    }
  }
  `;
  return {iri, id, query}
}
    
export const deleteOscalUserQuery = (id) => {
  const iri = `http://cyio.darklight.ai/oscal-user--${id}`;
  return deleteOscalUserByIriQuery(iri);
}

export const deleteOscalUserByIriQuery = (iri) => {
  if (!iri.startsWith('<')) iri = `<${iri}>`;
  return `
  DELETE {
    GRAPH ${iri} {
      ?iri ?p ?o
    }
  } WHERE {
    GRAPH ${iri} {
      ?iri a <http://csrc.nist.gov/ns/oscal/common#OscalUser> .
      ?iri ?p ?o
    }
  }
  `
}

export const deleteMultipleOscalUsersQuery = (ids) =>{
  const values = ids ? (ids.map((id) => `"${id}"`).join(' ')) : "";
  return `
  DELETE {
    GRAPH ?g {
      ?iri ?p ?o
    }
  } WHERE {
    GRAPH ?g {
      ?iri a <http://csrc.nist.gov/ns/oscal/common#OscalUser> .
      ?iri <http://darklight.ai/ns/common#id> ?id .
      ?iri ?p ?o .
      VALUES ?id {${values}}
    }
  }
  `
}

export const attachToOscalUserQuery = (id, field, itemIris) => {
  if (!oscalUserPredicateMap.hasOwnProperty(field)) return null;
  const iri = `<http://cyio.darklight.ai/oscal-user--${id}>`;
  const predicate = oscalUserPredicateMap[field].predicate;

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
    oscalUserPredicateMap, 
    '<http://csrc.nist.gov/ns/oscal/common#OscalUser>'
  );
}

export const detachFromOscalUserQuery = (id, field, itemIris) => {
  if (!oscalUserPredicateMap.hasOwnProperty(field)) return null;
  const iri = `<http://cyio.darklight.ai/oscal-user--${id}>`;
  const predicate = oscalUserPredicateMap[field].predicate;

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
    oscalUserPredicateMap, 
    '<http://csrc.nist.gov/ns/oscal/common#OscalUser>'
  );
}

//
// Query Builders - Authorized Privilege
//
export const selectAuthorizedPrivilegeQuery = (id, select) => {
  return selectAuthorizedPrivilegeByIriQuery(`http://cyio.darklight.ai/authorized-privilege--${id}`, select);
}

export const selectAuthorizedPrivilegeByIriQuery = (iri, select) => {
  if (!iri.startsWith('<')) iri = `<${iri}>`;
  if (select === undefined || select === null) select = Object.keys(authorizedPrivilegePredicateMap);

  // this is needed to assist in the determination of the type of the data source
  if (!select.includes('id')) select.push('id');
  if (!select.includes('object_type')) select.push('object_type');

  const { selectionClause, predicates } = buildSelectVariables(authorizedPrivilegePredicateMap, select);
  return `
  SELECT ?iri ${selectionClause}
  FROM <tag:stardog:api:context:local>
  WHERE {
    BIND(${iri} AS ?iri)
    ?iri a <http://csrc.nist.gov/ns/oscal/common#AuthorizedPrivilege> .
    ${predicates}
  }`
}

export const selectAllAuthorizedPrivilegesQuery = (select, args, parent) => {
  let constraintClause = '';
  if (select === undefined || select === null) select = Object.keys(authorizedPrivilegePredicateMap);
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
  const { selectionClause, predicates } = buildSelectVariables(authorizedPrivilegePredicateMap, select);

  return `
  SELECT DISTINCT ?iri ${selectionClause} 
  FROM <tag:stardog:api:context:local>
  WHERE {
    ?iri a <http://csrc.nist.gov/ns/oscal/common#AuthorizedPrivilege> . 
    ${predicates}
    ${constraintClause}
  }
  `
}

export const insertAuthorizedPrivilegeQuery = (propValues) => {
  const id = generateId( );

  // determine the appropriate ontology class type
  const iri = `<http://cyio.darklight.ai/authorized-privilege--${id}>`;
  const insertPredicates = [];
  Object.entries(propValues).forEach((propPair) => {
    if (authorizedPrivilegePredicateMap.hasOwnProperty(propPair[0])) {
      if (Array.isArray(propPair[1])) {
        for (let value of propPair[1]) {
          insertPredicates.push(authorizedPrivilegePredicateMap[propPair[0]].binding(iri, value));
        }  
      } else {
        insertPredicates.push(authorizedPrivilegePredicateMap[propPair[0]].binding(iri, propPair[1]));
      }
    }
  });

  const query = `
  INSERT DATA {
    GRAPH ${iri} {
      ${iri} a <http://csrc.nist.gov/ns/oscal/common#AuthorizedPrivilege> .
      ${iri} a <http://csrc.nist.gov/ns/oscal/common#ComplexDatatype> .
      ${iri} a <http://darklight.ai/ns/common#ComplexDatatype> .
      ${iri} <http://darklight.ai/ns/common#id> "${id}" .
      ${iri} <http://darklight.ai/ns/common#object_type> "authorized-privilege" . 
      ${insertPredicates.join(" . \n")}
    }
  }
  `;
  return {iri, id, query}
}
    
export const deleteAuthorizedPrivilegeQuery = (id) => {
  const iri = `http://cyio.darklight.ai/authorized-privilege--${id}`;
  return deleteAuthorizedPrivilegeByIriQuery(iri);
}

export const deleteAuthorizedPrivilegeByIriQuery = (iri) => {
  if (!iri.startsWith('<')) iri = `<${iri}>`;
  return `
  DELETE {
    GRAPH ${iri} {
      ?iri ?p ?o
    }
  } WHERE {
    GRAPH ${iri} {
      ?iri a <http://csrc.nist.gov/ns/oscal/common#AuthorizedPrivilege> .
      ?iri ?p ?o
    }
  }
  `
}

export const deleteMultipleAuthorizedPrivilegesQuery = (ids) =>{
  const values = ids ? (ids.map((id) => `"${id}"`).join(' ')) : "";
  return `
  DELETE {
    GRAPH ?g {
      ?iri ?p ?o
    }
  } WHERE {
    GRAPH ?g {
      ?iri a <http://csrc.nist.gov/ns/oscal/common#AuthorizedPrivilege> .
      ?iri <http://darklight.ai/ns/common#id> ?id .
      ?iri ?p ?o .
      VALUES ?id {${values}}
    }
  }
  `
}

export const attachToAuthorizedPrivilegeQuery = (id, field, itemIris) => {
  const iri = `<http://cyio.darklight.ai/authorized-privilege--${id}>`;
  if (!authorizedPrivilegePredicateMap.hasOwnProperty(field)) return null;
  const predicate = authorizedPrivilegePredicateMap[field].predicate;
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

  return attachQuery(iri, statements, authorizedPrivilegePredicateMap, '<http://csrc.nist.gov/ns/oscal/common#AuthorizedPrivilege>');
}

export const detachFromAuthorizedPrivilegeQuery = (id, field, itemIris) => {
  const iri = `<http://cyio.darklight.ai/authorized-privilege--${id}>`;
  if (!authorizedPrivilegePredicateMap.hasOwnProperty(field)) return null;
  const predicate = authorizedPrivilegePredicateMap[field].predicate;
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

  return detachQuery(iri, statements, authorizedPrivilegePredicateMap, '<http://csrc.nist.gov/ns/oscal/common#AuthorizedPrivilege>');
}


// Predicate Maps
export const oscalUserPredicateMap = {
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
    predicate: "<http://csrc.nist.gov/ns/oscal/common#name>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "name");},
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
  roles: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#roles>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "roles");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  authorized_privileges: {
    predicate: "<http://darklight.ai/ns/common#authorized_privileges>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "authorized_privileges");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  user_type: {
    predicate: "<http://darklight.ai/ns/common#user_type>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "user_type");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  privilege_level: {
    predicate: "<http://darklight.ai/ns/common#privilege_level>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "privilege_level");},
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

export const authorizedPrivilegePredicateMap = {
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
    predicate: "<http://csrc.nist.gov/ns/oscal/common#name>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "name");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  description: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#description>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"@en-US`: null, this.predicate, "description");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  functions_performed: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#functions_performed>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "functions_performed");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
};

// Serialization schema
export const singularizeOscalUserSchema = { 
  singularizeVariables: {
    "": false, // so there is an object as the root instead of an array
    "id": true,
    "iri": true,
    "object_type": true,
    "entity_type": true,
    "created": true,
    "modified": true,
    "user_type": true,
    "name": true,
    "short_name": true,
    "description": true,
    "privilege_level": true,
  }
};

export const singularizeAuthorizedPrivilegeSchema = { 
  singularizeVariables: {
    "": false, // so there is an object as the root instead of an array
    "id": true,
    "iri": true,
    "object_type": true,
    "entity_type": true,
    "name": true,
    "description": true,
  }
};
