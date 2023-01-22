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
    case 'DATA-SOURCE':
      return dataSourceReducer;
    case 'FREQUENCY-TIMING':
      return frequencyTimingReducer;
    default:
      throw new CyioError(`Unsupported reducer type ' ${type}'`)
  }
}

//
// Reducers
//
const dataSourceReducer = (item) => {
  // if no object type was returned, compute the type from the IRI
  if (item.object_type === undefined) {
    if (item.entity_type !== undefined) item.object_type = item.entity_type;
    if (item.iri.includes('data-source')) item.object_type = 'data-source';
  }

  return {
    iri: item.iri,
    id: item.id,
    ...(item.object_type && { entity_type: item.object_type }),
    ...(item.created && { created: item.created }),
    ...(item.modified && { modified: item.modified }),
    ...(item.name && { name: item.name }),
    ...(item.description && { description: item.description }),
    ...(item.data_source_type && { data_source_type: item.data_source_type }),
    ...(item.status && { status: item.status }),
    ...(item.contextual !== undefined && { contextual: item.contextual }),
    ...(item.auto !== undefined && { auto: item.auto }),
    ...(item.scope && { scope: item.scope }),
    ...(item.last_ingest_artifact && { last_ingest_artifact: item.last_ingest_artifact }),
    ...(item.last_success && { last_success: item.last_success }),
    ...(item.count && { count: item.count }),
    // hints for field-level resolver queries
    ...(item.update_frequency && { update_frequency_iri: item.update_frequency }),
    ...(item.connection_information && { connection_information_iri: item.connection_information }),
    ...(item.iep && { iep_iri: item.iep }),
    ...(item.external_references && { external_references_iri: item.external_references }),
    ...(item.notes && { notes_iri: item.notes }),
    ...(item.since && {since: item.since}),
  }
}

const frequencyTimingReducer = (item) => {
  // if no object type was returned, compute the type from the IRI
  if (item.object_type === undefined) {
    if (item.entity_type !== undefined) item.object_type = item.entity_type;
    if (item.iri.includes('frequency-timing')) item.object_type = 'frequency-timing';
  }

  return {
    iri: item.iri,
    id: item.id,
    ...(item.object_type && { entity_type: item.object_type }),
    ...(item.period && { period: item.period }),
    ...(item.unit && { unit: item.unit }),
  }
}


// Query Builders
export const insertDataSourceQuery = (propValues) => {
  const id_material = {
    ...(propValues.data_source_type && {"data_source_type": propValues.data_source_type}),
    ...(propValues.name && {"name": propValues.name}),
  } ;
  const id = generateId( id_material, DARKLIGHT_NS );
  const timestamp = new Date().toISOString();

  // determine the appropriate ontology class type
  const iri = `<http://cyio.darklight.ai/data-source--${id}>`;
  const insertPredicates = [];
  Object.entries(propValues).forEach((propPair) => {
    if (dataSourcePredicateMap.hasOwnProperty(propPair[0])) {
      if (Array.isArray(propPair[1])) {
        for (let value of propPair[1]) {
          insertPredicates.push(dataSourcePredicateMap[propPair[0]].binding(iri, value));
        }  
      } else {
        insertPredicates.push(dataSourcePredicateMap[propPair[0]].binding(iri, propPair[1]));
      }
    }
  });

  const query = `
  INSERT DATA {
    GRAPH ${iri} {
      ${iri} a <http://darklight.ai/ns/cyio/datasource#DataSource> .
      ${iri} a <http://darklight.ai/ns/common#Object> .
      ${iri} <http://darklight.ai/ns/common#id> "${id}" .
      ${iri} <http://darklight.ai/ns/common#object_type> "data-source" . 
      ${iri} <http://darklight.ai/ns/common#created> "${timestamp}"^^xsd:dateTime . 
      ${iri} <http://darklight.ai/ns/common#modified> "${timestamp}"^^xsd:dateTime . 
      ${insertPredicates.join(" . \n")}
    }
  }
  `;
  return {iri, id, query}
}

export const selectDataSourceQuery = (id, select) => {
  return selectDataSourceByIriQuery(`http://cyio.darklight.ai/data-source--${id}`, select);
}

export const selectDataSourceByIriQuery = (iri, select) => {
  if (!iri.startsWith('<')) iri = `<${iri}>`;
  if (select === undefined || select === null) select = Object.keys(dataSourcePredicateMap);

  // this is needed to assist in the determination of the type of the data source
  if (!select.includes('id')) select.push('id');
  if (!select.includes('object_type')) select.push('object_type');
  if (!select.includes('type')) select.push('type');

  const { selectionClause, predicates } = buildSelectVariables(dataSourcePredicateMap, select);
  return `
  SELECT ?iri ${selectionClause}
  FROM <tag:stardog:api:context:local>
  WHERE {
    BIND(${iri} AS ?iri)
    ?iri a <http://darklight.ai/ns/cyio/datasource#DataSource> .
    ${predicates}
  }`
}

export const selectAllDataSourcesQuery = (select, args, parent) => {
  let constraintClause = '';
  if (select === undefined || select === null) select = Object.keys(dataSourcePredicateMap);
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

  const { selectionClause, predicates } = buildSelectVariables(dataSourcePredicateMap, select);

  // add constraint clause to limit to those that are referenced by the specified parent
  if (parent !== undefined && parent.iri !== undefined) {
    // define a constraint to limit retrieval to only those referenced by the parent
    constraintClause = `
    {
      SELECT DISTINCT ?iri
      WHERE {
          <${parent.iri}> a <http://darklight.ai/ns/cyio/system-configuration#SystemConfiguration> ;
          <<http://darklight.ai/ns/cyio/system-configuration#data_sources> ?iri .
      }
    }`;
  }

  return `
  SELECT DISTINCT ?iri ${selectionClause} 
  FROM <tag:stardog:api:context:local>
  WHERE {
    ?iri a <http://darklight.ai/ns/cyio/datasource#DataSource> . 
    ${predicates}
    ${constraintClause}
  }
  `
}

export const deleteDataSourceQuery = (id) => {
  const iri = `http://cyio.darklight.ai/data-source--${id}`;
  return deleteDataSourceByIriQuery(iri);
}

export const deleteDataSourceByIriQuery = (iri) => {
  if (!iri.startsWith('<')) iri = `<${iri}>`;
  return `
  DELETE {
    GRAPH ${iri} {
      ?iri ?p ?o
    }
  } WHERE {
    GRAPH ${iri} {
      ?iri a <http://darklight.ai/ns/cyio/datasource#DataSource> .
      ?iri ?p ?o
    }
  }
  `
}

export const deleteMultipleDataSourcesQuery = (ids) =>{
  const values = ids ? (ids.map((id) => `"${id}"`).join(' ')) : "";
  return `
  DELETE {
    GRAPH ?g {
      ?iri ?p ?o
    }
  } WHERE {
    GRAPH ?g {
      ?iri a <http://darklight.ai/ns/cyio/datasource#DataSource> .
      ?iri <http://darklight.ai/ns/common#id> ?id .
      ?iri ?p ?o .
      VALUES ?id {${values}}
    }
  }
  `
}

export const attachToDataSourceQuery = (id, field, itemIris) => {
  const iri = `<http://cyio.darklight.ai/data-source--${id}>`;
  if (!dataSourcePredicateMap.hasOwnProperty(field)) return null;
  const predicate = dataSourcePredicateMap[field].predicate;
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

export const detachFromDataSourceQuery = (id, field, itemIris) => {
  const iri = `<http://cyio.darklight.ai/data-source--${id}>`;
  if (!dataSourcePredicateMap.hasOwnProperty(field)) return null;
  const predicate = dataSourcePredicateMap[field].predicate;
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


export const insertFrequencyTimingQuery = (propValues) => {
  const id = generateId( );

  // determine the appropriate ontology class type
  const iri = `<http://cyio.darklight.ai/frequency-timing--${id}>`;
  const insertPredicates = [];
  Object.entries(propValues).forEach((propPair) => {
    if (frequencyTimingPredicateMap.hasOwnProperty(propPair[0])) {
      if (Array.isArray(propPair[1])) {
        for (let value of propPair[1]) {
          insertPredicates.push(frequencyTimingPredicateMap[propPair[0]].binding(iri, value));
        }  
      } else {
        insertPredicates.push(frequencyTimingPredicateMap[propPair[0]].binding(iri, propPair[1]));
      }
    }
  });

  const query = `
  INSERT DATA {
    GRAPH ${iri} {
      ${iri} a <http://darklight.ai/ns/cyio/datasource#FrequencyTiming> .
      ${iri} a <http://darklight.ai/ns/common#ComplexDatatype> .
      ${iri} <http://darklight.ai/ns/common#id> "${id}".
      ${iri} <http://darklight.ai/ns/common#object_type> "frequency-timing" . 
      ${insertPredicates.join(". \n")}
    }
  }
  `;
  return {iri, id, query}
}

export const selectFrequencyTimingQuery = (id, select) => {
  return selectDataSourceByIriQuery(`http://cyio.darklight.ai/frequency-timing--${id}`, select);
}

export const selectFrequencyTimingByIriQuery = (iri, select) => {
  if (!iri.startsWith('<')) iri = `<${iri}>`;
  if (select === undefined || select === null) select = Object.keys(frequencyTimingPredicateMap);

  // this is needed to assist in the determination of the type of the data source
  if (!select.includes('id')) select.push('id');
  if (!select.includes('object_type')) select.push('object_type');

  const { selectionClause, predicates } = buildSelectVariables(frequencyTimingPredicateMap, select);
  return `
  SELECT ?iri ${selectionClause}
  FROM <tag:stardog:api:context:local>
  WHERE {
    BIND(${iri} AS ?iri)
    ?iri a <http://darklight.ai/ns/cyio/datasource#FrequencyTiming> .
    ${predicates}
  }`
}

export const deleteFrequencyTimingQuery = (id) => {
  const iri = `http://cyio.darklight.ai/frequency-timing--${id}`;
  return deleteDataSourceByIriQuery(iri);
}

export const deleteFrequencyTimingByIriQuery = (iri) => {
  if (!iri.startsWith('<')) iri = `<${iri}>`;
  return `
  DELETE {
    GRAPH ${iri} {
      ?iri ?p ?o
    }
  } WHERE {
    GRAPH ${iri} {
      ?iri a <http://darklight.ai/ns/cyio/datasource#FrequencyTiming> .
      ?iri ?p ?o
    }
  }
  `
}


// Predicate Maps
export const dataSourcePredicateMap = {
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
    predicate: "<http://darklight.ai/ns/cyio/datasource#name>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "name");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  description: {
    predicate: "<http://darklight.ai/ns/cyio/datasource#description>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"@en-US` : null,  this.predicate, "description");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  data_source_type: {
    predicate: "<http://darklight.ai/ns/cyio/datasource#data_source_type>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "data_source_type");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  status: {
    predicate: "<http://darklight.ai/ns/cyio/datasource#status>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "status");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  contextual: {
    predicate: "<http://darklight.ai/ns/cyio/datasource#contextual>",
    binding: function (iri, value) { return parameterizePredicate(iri, value !== undefined ? `"${value}"^^xsd:boolean` : null,  this.predicate, "contextual");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  auto: {
    predicate: "<http://darklight.ai/ns/cyio/datasource#auto>",
    binding: function (iri, value) { return parameterizePredicate(iri, value !== undefined ? `"${value}"^^xsd:boolean` : null,  this.predicate, "auto");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  scope: {
    predicate: "<http://darklight.ai/ns/cyio/datasource#scope>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "scope");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  last_ingest_artifact: {
    predicate: "<http://darklight.ai/ns/cyio/datasource#last_ingest_artifact>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "last_ingest_artifact");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  last_success: {
    predicate: "<http://darklight.ai/ns/cyio/datasource#last_success>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime` : null,  this.predicate, "last_success");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  update_frequency: {
    predicate: "<http://darklight.ai/ns/cyio/datasource#update_frequency>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "update_frequency");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  connection_information: {
    predicate: "<http://darklight.ai/ns/cyio/datasource#connection_information>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "connection_information");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  iep: {
    predicate: "<http://darklight.ai/ns/cyio/datasource#iep>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "iep");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  external_references: {
    predicate: "<http://darklight.ai/ns/cyio/datasource#external_references>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "external_references");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  notes: {
    predicate: "<http://darklight.ai/ns/cyio/datasource#notes>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "notes");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  // relationships: {
  //   predicate: "<http://darklight.ai/ns/common#relationships>",
  //   binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "relationships");},
  //   optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  // },
}

export const frequencyTimingPredicateMap = {
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
  period: {
    predicate: "<http://darklight.ai/ns/cyio/datasource#period>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "period");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  unit: {
    predicate: "<http://darklight.ai/ns/cyio/datasource#unit>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "unit");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
};


export const singularizeSchema = { 
  singularizeVariables: {
    "": false, // so there is an object as the root instead of an array
    "id": true,
    "iri": true,
    "object_type": true,
    "entity_type": true,
    "created": true,
    "modified": true,
    "data_source_type": true,
    "name": true,
    "description": true,
    "status": true,
    "contextual": true,
    "auto": true,
    "last_ingest_artifact": true,
    "last_success": true,
    "update_frequency": true,
    "connection_information": true,
    "iep": true,
    "unit": true,
    "period": true,
  }
};

