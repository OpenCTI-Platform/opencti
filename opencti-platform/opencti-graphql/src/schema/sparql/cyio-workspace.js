import { optionalizePredicate, parameterizePredicate, buildSelectVariables, generateId, CyioError } from '../../cyio/schema/utils.js';
import { selectObjectIriByIdQuery } from '../../cyio/schema/global/global-utils.js';

// Reducer Selection
export function getReducer(type) {
  switch (type) {
    case 'WORKSPACE':
      return workspaceReducer;
    default:
      throw new Error(`Unsupported reducer type ' ${type}'`)
  }
}

//
// Reducers
//
const workspaceReducer = (item) => {
  // if no object type was returned, compute the type from the IRI
  if (item.object_type === undefined) {
    if (item.entity_type !== undefined) item.object_type = item.entity_type;
    if (item.iri.includes('workspace')) item.object_type = 'workspace';
  }

  return {
    iri: item.iri,
    id: item.id,
    ...(item.object_type && { "entity_type": item.object_type }),
    ...(item.created_at && {created_at: item.created_at}),
    ...(item.updated_at && {updated_at: item.updated_at}),
    ...(item.type && { type: item.type }),
    ...(item.name && { "name": item.name }),
    ...(item.description && { description: item.description }),
    ...(item.owner && { owner: item.owner }),
    ...(item.tags && { tags: item.tags }),
    ...(item.manifest && {manifest: item.manifest}),
    ...(item.graph_data && {graph_data: item.graph_data}),
    // hints
    ...(item.edit_context && {edit_context_iri: item.edit_context}),
    ...(item.objects && {objects_iri: item.objects}),
  }
}

// Query Builders
export const insertWorkspaceQuery = (propValues) => {
  const id = generateId( );
  const timestamp = new Date().toISOString();

  // determine the appropriate ontology class type
  const iri = `<http://cyio.darklight.ai/workspace--${id}>`;
  const insertPredicates = [];
  Object.entries(propValues).forEach((propPair) => {
    if (workspacePredicateMap.hasOwnProperty(propPair[0])) {
      if (Array.isArray(propPair[1])) {
        for (let value of propPair[1]) {
          insertPredicates.push(workspacePredicateMap[propPair[0]].binding(iri, value));
        }  
      } else {
        insertPredicates.push(workspacePredicateMap[propPair[0]].binding(iri, propPair[1]));
      }
    }
  });

  const query = `
  INSERT DATA {
    GRAPH ${iri} {
      ${iri} a <http://darklight.ai/ns/cyio/workspace#Workspace> .
      ${iri} a <http://darklight.ai/ns/common#Object> .
      ${iri} <http://darklight.ai/ns/common#id> "${id}".
      ${iri} <http://darklight.ai/ns/common#object_type> "workspace" . 
      ${iri} <http://darklight.ai/ns/common#created> "${timestamp}"^^xsd:dateTime . 
      ${iri} <http://darklight.ai/ns/common#modified> "${timestamp}"^^xsd:dateTime . 
      ${insertPredicates.join(". \n")}
    }
  }
  `;
  return {iri, id, query}
}

export const selectWorkspaceQuery = (id, select) => {
  return selectWorkspaceByIriQuery(`http://cyio.darklight.ai/workspace--${id}`, select);
}

export const selectWorkspaceByIriQuery = (iri, select) => {
  if (!iri.startsWith('<')) iri = `<${iri}>`;
  if (select === undefined || select === null) select = Object.keys(workspacePredicateMap);

  // this is needed to assist in the determination of the type of the workspace
  if (!select.includes('id')) select.push('id');
  if (!select.includes('object_type')) select.push('object_type');
  if (!select.includes('type')) select.push('type');

  const { selectionClause, predicates } = buildSelectVariables(workspacePredicateMap, select);
  return `
  SELECT ?iri ${selectionClause}
  FROM <tag:stardog:api:context:local>
  WHERE {
    BIND(${iri} AS ?iri)
    ?iri a <http://darklight.ai/ns/cyio/workspace#Workspace> .
    ${predicates}
  }`
}

export const selectAllWorkspacesQuery = (select, args, parent) => {
  let constraintClause = '';
  if (select === undefined || select === null) select = Object.keys(workspacePredicateMap);
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

  const { selectionClause, predicates } = buildSelectVariables(workspacePredicateMap, select);

  // add constraint clause to limit to those that are referenced by the specified POAM
  if (parent !== undefined && parent.iri !== undefined) {
    // define a constraint to limit retrieval to only those referenced by the parent
    constraintClause = `
    {
      SELECT DISTINCT ?iri
      WHERE {
          <${parent.iri}> a <http://darklight.ai/ns/cyio/system-configuration#SystemConfiguration> ;
          <<http://darklight.ai/ns/cyio/system-configuration#workspaces> ?iri .
      }
    }`;
  }

  return `
  SELECT DISTINCT ?iri ${selectionClause} 
  FROM <tag:stardog:api:context:local>
  WHERE {
    ?iri a <http://darklight.ai/ns/cyio/workspace#Workspace> . 
    ${predicates}
    ${constraintClause}
  }
  `
}

export const deleteWorkspaceQuery = (id) => {
  const iri = `http://cyio.darklight.ai/workspace--${id}`;
  return deleteWorkspaceByIriQuery(iri);
}

export const deleteWorkspaceByIriQuery = (iri) => {
  if (!iri.startsWith('<')) iri = `<${iri}>`;
  return `
  DELETE {
    GRAPH ${iri} {
      ?iri ?p ?o
    }
  } WHERE {
    GRAPH ${iri} {
      ?iri a <http://darklight.ai/ns/cyio/workspace#Workspace> .
      ?iri ?p ?o
    }
  }
  `
}

export const attachToWorkspaceQuery = (id, field, itemIris) => {
  const iri = `<http://cyio.darklight.ai/workspace--${id}>`;
  if (!workspacePredicateMap.hasOwnProperty(field)) return null;
  const predicate = workspacePredicateMap[field].predicate;
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

export const detachFromWorkspaceQuery = (id, field, itemIris) => {
  const iri = `<http://cyio.darklight.ai/workspace--${id}>`;
  if (!workspacePredicateMap.hasOwnProperty(field)) return null;
  const predicate = workspacePredicateMap[field].predicate;
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
export const workspacePredicateMap = {
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
  created_at: {
    predicate: "<http://darklight.ai/ns/common#created>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime` : null,  this.predicate, "created_at");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  updated_at: {
    predicate: "<http://darklight.ai/ns/common#modified>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime` : null,  this.predicate, "updated_at");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  type: {
      predicate: "<http://darklight.ai/ns/cyio/workspace#type>",
      binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "type");},
      optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  name: {
    predicate: "<http://darklight.ai/ns/cyio/workspace#name>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "name");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  description: {
    predicate: "<http://darklight.ai/ns/cyio/workspace#description>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "description");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  owner: {
    predicate: "<http://darklight.ai/ns/cyio/workspace#owner>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "owner");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  tags: {
    predicate: "<http://darklight.ai/ns/cyio/workspace#tags>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "tags");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  manifest: {
    predicate: "<http://darklight.ai/ns/cyio/workspace#manifest>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:base64Binary`: null, this.predicate, "manifest");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  editContext: {
    predicate: "<http://darklight.ai/ns/cyio#edit_context>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "edit_context");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  objects: {
    predicate: "<http://darklight.ai/ns/cyio/workspace#objects>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "objects");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  graph_data: {
    predicate: "<http://darklight.ai/ns/cyio/workspace#graph_data>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:base64Binary`: null, this.predicate, "graph_data");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  // relationships: {
  //   predicate: "<http://darklight.ai/ns/common#relationships>",
  //   binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "relationships");},
  //   optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  // },
}

export const singularizeSchema = { 
  singularizeVariables: {
    "": false, // so there is an object as the root instead of an array
    "id": true,
    "iri": true,
    "object_type": true,
    "entity_type": true,
    "created": true,
    "created_at": true,
    "modified": true,
    "updated_at": true,
    "type": true,
    "name": true,
    "description": true,
    "owner": true,
    "manifest": true,
    "graph_data": true,
    "objects": false,
    "edit_context": false,
    "tags": false,
  }
};