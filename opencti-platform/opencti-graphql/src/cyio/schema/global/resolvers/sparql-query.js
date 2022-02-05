import {byIdClause, optionalizePredicate, parameterizePredicate, buildSelectVariables, generateId, OASIS_NS} from "../../utils.js";


// Reducer Selection
export function getReducer( type ) {
  switch( type ) {
    case 'EXTERNAL-REFERENCE':
      return externalReferenceReducer;
    case 'LABEL':
      return labelReducer;
    case 'NOTE':
      return noteReducer;
    default:
      throw new Error(`Unsupported reducer type ' ${type}'`)
  }
}


//
// Reducers
//
const externalReferenceReducer = (item) => {
  // if no object type was returned, compute the type from the IRI
  if ( item.object_type === undefined && item.asset_type !== undefined ) {
    item.object_type = item.asset_type
  } else {
    item.object_type = 'external-reference';
  }

  return {
    id: item.id,
    ...(item.object_type && {"entity_type": item.object_type}),
    ...(item.created && {"created": item.created}),
    ...(item.modified && {"modified": item.modified}),
    // External Reference
    ...(item.source_name && {"source_name": item.source_name} ),
    ...(item.description && {"description": item.description}),
    ...(item.url && {"url": item.url}),
    ...(item.external_id && {"external_id": item.external_id}),
    // OSCAL Link
    ...(item.reference_purpose && {"reference_purpose": item.reference_purpose}),
    ...(item.media_type && {"media_type": item.media_type}),
    //HINTS
    ...(item.hashes && {hashes_iri: item.hashes}),
  }
}

const labelReducer = (item) => {
  // if no object type was returned, compute the type from the IRI
  if ( item.object_type === undefined && item.asset_type !== undefined ) {
    item.object_type = item.asset_type
  } else {
    item.object_type = 'label';
  }

  return {
    id: item.id,
    ...(item.object_type && {"entity_type": item.object_type}),
    ...(item.created && {"created": item.created}),
    ...(item.modified && {"modified": item.modified}),
    ...(item.name && {"name": item.name} ),
    ...(item.description && {"description": item.description}),
    // Label
    ...(item.color && {"color": item.color}),
  }
}

const noteReducer = (item) => {
  // if no object type was returned, compute the type from the IRI
  if ( item.object_type === undefined && item.asset_type !== undefined ) {
    item.object_type = item.asset_type
  } else {
    item.object_type = 'note';
  }

  return {
    id: item.id,
    ...(item.object_type && {"entity_type": item.object_type}),
    ...(item.created && {"created": item.created}),
    ...(item.modified && {"modified": item.modified}),
    // Note
    ...(item.abstract && {"abstract": item.abstract} ),
    ...(item.content && {"content": item.content}),
    ...(item.authors && {"authors": item.authors}),
    // HINTS
    ...(item.labels && {labels_iri: item.labels}),
  }
}


//
//  Predicate Maps
//
export const externalReferencePredicateMap = {
  id: {
    predicate: "<http://darklight.ai/ns/common#id>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "id")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
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
  source_name: {
    predicate: "<http://darklight.ai/ns/common#source_name>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "source_name");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  description: {
    predicate: "<http://darklight.ai/ns/common#description>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "description");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  url: {
    predicate: "<http://darklight.ai/ns/common#url>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:anyURI` : null,  this.predicate, "url");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  hashes: {
    predicate: "<http://darklight.ai/ns/common#hashes>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "hashes");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  external_id: {
    predicate: "<http://darklight.ai/ns/common#external_id>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "external_id");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  reference_purpose: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#description>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "reference_purpose");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  media_type: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#media_type>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "media_type");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
}

export const labelPredicateMap = {
  id: {
    predicate: "<http://darklight.ai/ns/common#id>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "id")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
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
  name: {
    predicate: "<http://darklight.ai/ns/common#name>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "name");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  description: {
    predicate: "<http://darklight.ai/ns/common#description>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "description");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  color: {
    predicate: "<http://darklight.ai/ns/common#color>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "color");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
}

export const notePredicateMap = {
  id: {
    predicate: "<http://darklight.ai/ns/common#id>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "id")},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value))}
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
  abstract: {
    predicate: "<http://darklight.ai/ns/common#abstract>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "abstract");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  content: {
    predicate: "<http://darklight.ai/ns/common#content>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "content");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  authors: {
    predicate: "<http://darklight.ai/ns/common#authors>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "authors");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  labels: {
    predicate: "<http://darklight.ai/ns/common#labels>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "labels");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
}

// Label support functions
export const insertLabelQuery = (propValues) => {
  const id_material = {
    ...(propValues.name && {"name": propValues.name}),
  } ;
  const id = generateId( id_material, OASIS_NS );
  const timestamp = new Date().toISOString()
  const iri = `<http://darklight.ai/ns/common#Label-${id}>`;
  const insertPredicates = Object.entries(propValues)
      .filter((propPair) => labelPredicateMap.hasOwnProperty(propPair[0]))
      .map((propPair) => labelPredicateMap[propPair[0]].binding(iri, propPair[1]))
      .join('. \n      ');
  const query = `
  INSERT DATA {
    GRAPH ${iri} {
      ${iri} a <http://darklight.ai/ns/common#Label> .
      ${iri} a <http://darklight.ai/ns/common#ComplexDatatype> .
      ${iri} a <http://darklight.ai/ns/common#Object> .
      ${iri} <http://darklight.ai/ns/common#id> "${id}".
      ${iri} <http://darklight.ai/ns/common#object_type> "label" . 
      ${iri} <http://darklight.ai/ns/common#created> "${timestamp}"^^xsd:dateTime . 
      ${iri} <http://darklight.ai/ns/common#modified> "${timestamp}"^^xsd:dateTime . 
      ${insertPredicates}
    }
  }
  `;
  return {iri, id, query}
}

export const selectLabelQuery = (id, select) => {
  return selectLabelByIriQuery(`http://darklight.ai/ns/common#Label-${id}`, select);
}

export const selectLabelByIriQuery = (iri, select) => {
  // IRI is expected to not include < or >
  if(select === null) select = Object.keys(labelPredicateMap);
  const { selectionClause, predicates } = buildSelectVariables(labelPredicateMap, select);
  return `
  SELECT ${selectionClause}
  FROM <tag:stardog:api:context:named>
  WHERE {
    ?iri a <http://darklight.ai/ns/common#Label> .
    ${predicates}
  }
  `
}

export const selectAllLabels = (select) => {
  if(select === null) select =Object.keys(labelPredicateMap);
  const { selectionClause, predicates } = buildSelectVariables(labelPredicateMap, select);
  return `
  SELECT DISTINCT ?iri ${selectionClause} 
  FROM <tag:stardog:api:context:named>
  WHERE {
    ?iri a <http://darklight.ai/ns/common#Label> . 
    ${predicates}
  }
  `
}

export const deleteLabelQuery = (id) => {
  const iri = `<http://darklight.ai/ns/common#Label-${id}>`;
  return `
  DELETE {
    GRAPH ${iri}{
      ?iri ?p ?o
    }
  } WHERE {
    GRAPH ${iri}{
      ?iri a <http://darklight.ai/ns/common#Label> .
      ?iri ?p ?o
    }
  }
  `
}

// External Reference support functions
export const insertExternalReferenceQuery = (propValues) => {
  const id_material = {
    ...(propValues.source_name && {"source_name": propValues.source_name}),
    ...(propValues.external_id && {"external_id": propValues.external_id}),
    ...(propValues.url && {"url": propValues.url}),
  } ;
  const id = generateId( id_material, OASIS_NS );
  const timestamp = new Date().toISOString()
  const iri = `<http://darklight.ai/ns/common#ExternalReference-${id}>`;
  const insertPredicates = Object.entries(propValues)
      .filter((propPair) => externalReferencePredicateMap.hasOwnProperty(propPair[0]))
      .map((propPair) => externalReferencePredicateMap[propPair[0]].binding(iri, propPair[1]))
      .join('. \n      ');
  const query = `
  INSERT DATA {
    GRAPH ${iri} {
      ${iri} a <http://darklight.ai/ns/common#ExternalReference> .
      ${iri} a <http://darklight.ai/ns/common#ComplexDatatype> .
      ${iri} a <http://darklight.ai/ns/common#Object> .
      ${iri} <http://darklight.ai/ns/common#id> "${id}".
      ${iri} <http://darklight.ai/ns/common#object_type> "external-reference" . 
      ${iri} <http://darklight.ai/ns/common#created> "${timestamp}"^^xsd:dateTime . 
      ${iri} <http://darklight.ai/ns/common#modified> "${timestamp}"^^xsd:dateTime . 
      ${insertPredicates}
    }
  }
  `;
  return {iri, id, query}
}

export const selectExternalReferenceQuery = (id, select) => {
  return selectExternalReferenceByIriQuery(`http://darklight.ai/ns/common#ExternalReference-${id}`, select);
}

export const selectExternalReferenceByIriQuery = (iri, select) => {
  // IRI is expected to not include < or >
  if(select === null) select = Object.keys(externalReferencePredicateMap);
  const { selectionClause, predicates } = buildSelectVariables(externalReferencePredicateMap, select);
  return `
  SELECT ${selectionClause}
  FROM <tag:stardog:api:context:named>
  WHERE {
    ?iri a <http://darklight.ai/ns/common#ExternalReference> .
    ${predicates}
  }
  `
}

export const selectAllExternalReferences = (select) => {
  if(select === null) select =Object.keys(externalReferencePredicateMap);
  const { selectionClause, predicates } = buildSelectVariables(externalReferencePredicateMap, select);
  return `
  SELECT DISTINCT ?iri ${selectionClause} 
  FROM <tag:stardog:api:context:named>
  WHERE {
    ?iri a <http://darklight.ai/ns/common#ExternalReference> . 
    ${predicates}
  }
  `
}

export const deleteExternalReferenceQuery = (id) => {
  const iri = `<http://darklight.ai/ns/common#ExternalReference-${id}>`;
  return `
  DELETE {
    GRAPH ${iri}{
      ?iri ?p ?o
    }
  } WHERE {
    GRAPH ${iri}{
      ?iri a <http://darklight.ai/ns/common#ExternalReference> .
      ?iri ?p ?o
    }
  }
  `
}

// Note support functions
export const insertNoteQuery = (propValues) => {
  const id_material = {
    ...(propValues.abstract && {"abstract": propValues.abstract}),
    ...(propValues.authors && {"authors": propValues.authors}),
    ...(propValues.content && {"content": propValues.content}),
  } ;
  const id = generateId( id_material, OASIS_NS );
  const timestamp = new Date().toISOString()
  const iri = `<http://darklight.ai/ns/common#Note-${id}>`;
  const insertPredicates = Object.entries(propValues)
      .filter((propPair) => notePredicateMap.hasOwnProperty(propPair[0]))
      .map((propPair) => notePredicateMap[propPair[0]].binding(iri, propPair[1]))
      .join('. \n      ');
  const query = `
  INSERT DATA {
    GRAPH ${iri} {
      ${iri} a <http://darklight.ai/ns/common#Note> .
      ${iri} a <http://darklight.ai/ns/common#Object> .
      ${iri} <http://darklight.ai/ns/common#id> "${id}".
      ${iri} <http://darklight.ai/ns/common#object_type> "note" . 
      ${iri} <http://darklight.ai/ns/common#created> "${timestamp}"^^xsd:dateTime . 
      ${iri} <http://darklight.ai/ns/common#modified> "${timestamp}"^^xsd:dateTime . 
      ${insertPredicates}
    }
  }
  `;
  return {iri, id, query}
}

export const selectNoteQuery = (id, select) => {
  return selectNoteByIriQuery(`http://darklight.ai/ns/common#Note-${id}`, select);
}

export const selectNoteByIriQuery = (iri, select) => {
  // IRI is expected to not include < or >
  if(select === null) select = Object.keys(notePredicateMap);
  const { selectionClause, predicates } = buildSelectVariables(notePredicateMap, select);
  return `
  SELECT ${selectionClause}
  FROM <tag:stardog:api:context:named>
  WHERE {
    ?iri a <http://darklight.ai/ns/common#Note> .
    ${predicates}
  }
  `
}

export const selectAllNotes = (select) => {
  if(select === null) select =Object.keys(notePredicateMap);
  const { selectionClause, predicates } = buildSelectVariables(notePredicateMap, select);
  return `
  SELECT DISTINCT ?iri ${selectionClause} 
  FROM <tag:stardog:api:context:named>
  WHERE {
    ?iri a <http://darklight.ai/ns/common#Note> . 
    ${predicates}
  }
  `
}

export const deleteNoteQuery = (id) => {
  const iri = `<http://darklight.ai/ns/common#Note-${id}>`;
  return `
  DELETE {
    GRAPH ${iri}{
      ?iri ?p ?o
    }
  } WHERE {
    GRAPH ${iri}{
      ?iri a <http://darklight.ai/ns/common#Note> .
      ?iri ?p ?o
    }
  }
  `
}
