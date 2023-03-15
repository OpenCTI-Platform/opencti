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
    case 'INFORMATION-TYPE':
      return informationTypeReducer;
		case 'IMPACT-DEFINITION':
			return impactDefinitionReducer;
    case 'CATEGORIZATION':
      return categorizationReducer;
    default:
      throw new UserInputError(`Unsupported reducer type ' ${type}'`)
  }
}
    
//
// Reducers
//
const informationTypeReducer = (item) => {
  // if no object type was returned, compute the type from the IRI
  if (item.object_type === undefined) {
      if (item.entity_type !== undefined) item.object_type = item.entity_type;
      if (item.iri.includes('information-type')) item.object_type = 'information-type';
  }

  return {
      iri: item.iri,
      id: item.id,
      ...(item.object_type && { entity_type: item.object_type }),
      ...(item.created && { created: item.created }),
      ...(item.modified && { modified: item.modified }),
      ...(item.display_name && { display_name: item.display_name }),
			...(item.title && { title: item.title }),
			...(item.description && { description: item.description }),
      ...(item.identifier && { identifier: item.identifier }),
      ...(item.system && { system: item.system }),
      ...(item.category && { category: item.category }),
			// prefetched 
			...(item.confidentiality_base_impact && { confidentiality_base_impact: item.confidentiality_base_impact }),
			...(item.confidentiality_selected_impact && { confidentiality_selected_impact: item.confidentiality_selected_impact }),
			...(item.confidentiality_adjustment_justification && { confidentiality_adjustment_justification: item.confidentiality_adjustment_justification }),
			...(item.integrity_base_impact && { integrity_base_impact: item.integrity_base_impact }),
			...(item.integrity_selected_impact && { integrity_selected_impact: item.integrity_selected_impact }),
			...(item.integrity_adjustment_justification && { integrity_adjustment_justification: item.integrity_adjustment_justification }),
			...(item.availability_base_impact && { availability_base_impact: item.availability_base_impact }),
			...(item.availability_selected_impact && { availability_selected_impact: item.availability_selected_impact }),
			...(item.availability_adjustment_justification && { availability_adjustment_justification: item.availability_adjustment_justification }),
      // hints for field-level resolver queries
      ...(item.categorizations && { categorization_iris: item.categorizations }),
      ...(item.confidentiality_impact && { confidentiality_impact_iri: item.confidentiality_impact }),
      ...(item.integrity_impact && { integrity_impact_iri: item.integrity_impact }),
      ...(item.availability_impact && { availability_impact_iri: item.availability_impact }),
      ...(item.labels && { labels_iris: item.labels }),
      ...(item.links && { links_iris: item.links }),
      ...(item.remarks && { remarks_iris: item.remarks }),
			...(item.relationships && { relationships: item.relationships }),
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
			...(item.base_impact && { base_impact: item.base_impact }),
			...(item.selected_impact && { selected_impact: item.selected_impact }),
			...(item.adjustment_justification && { adjustment_justification: item.adjustment_justification }),
      ...(item.explanation && { explanation: item.explanation }),
      ...(item.recommendation && { recommendation: item.recommendation }),
      // hints for field-level resolver queries
      ...(item.links && { links_iris: item.links }),
			...(item.relationships && { relationships: item.relationships }),
		}
};
const categorizationReducer = (item) => {
  // if no object type was returned, compute the type from the IRI
  if (item.object_type === undefined) {
      if (item.entity_type !== undefined) item.object_type = item.entity_type;
      if (item.iri.includes('categorization')) item.object_type = 'categorization';
  }

  return {
      iri: item.iri,
      id: item.id,
      ...(item.object_type && { entity_type: item.object_type }),
      ...(item.system && { system: item.system }),
      // hints for field-level resolver queries
      ...(item.catalog && { catalog_iri: item.catalog }),
			...(item.information_type && { information_type_iri: item.information_type }),
		}
};

// Utility
export const getInformationTypeIri = (id) => {
  // ensure the id is a valid UUID
  if (!checkIfValidUUID(id)) throw new UserInputError(`Invalid identifier: ${id}`);
  return `<http://cyio.darklight.ai/information-type--${id}>`;
}
export const getImpactDefinitionIri = (id) => {
  // ensure the id is a valid UUID
  if (!checkIfValidUUID(id)) throw new UserInputError(`Invalid identifier: ${id}`);
  return `<http://cyio.darklight.ai/impact-definition--${id}>`;
}
export const getCategorizationIri = (id) => {
  // ensure the id is a valid UUID
  if (!checkIfValidUUID(id)) throw new UserInputError(`Invalid identifier: ${id}`);
  return `<http://cyio.darklight.ai/categorization--${id}>`;
}


// Query Builders - Information Type
export const selectInformationTypeQuery = (id, select) => {
  return selectInformationTypeByIriQuery(`http://cyio.darklight.ai/information-type--${id}`, select);
}

export const selectInformationTypeByIriQuery = (iri, select) => {
  if (!iri.startsWith('<')) iri = `<${iri}>`;
  if (select === undefined || select === null) select = Object.keys(informationTypePredicateMap);

  // this is needed to assist in the determination of the type of the data source
  if (!select.includes('id')) select.push('id');
  if (!select.includes('object_type')) select.push('object_type');

  const { selectionClause, predicates } = buildSelectVariables(informationTypePredicateMap, select);
  return `
  SELECT ?iri ${selectionClause}
  FROM <tag:stardog:api:context:local>
  WHERE {
    BIND(${iri} AS ?iri)
    ?iri a <http://csrc.nist.gov/ns/oscal/info-system#InformationType> .
    ${predicates}
  }`
}

export const selectAllInformationTypesQuery = (select, args, parent) => {
  let constraintClause = '';
  if (select === undefined || select === null) select = Object.keys(informationTypePredicateMap);
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
  const { selectionClause, predicates } = buildSelectVariables(informationTypePredicateMap, select);

  return `
  SELECT DISTINCT ?iri ${selectionClause} 
  FROM <tag:stardog:api:context:local>
  WHERE {
    ?iri a <http://csrc.nist.gov/ns/oscal/info-system#InformationType> . 
    ${predicates}
    ${constraintClause}
  }
  `
}

export const insertInformationTypeQuery = (propValues) => {
  const id_material = {
    ...(propValues.title && {"title": propValues.title}),
  } ;
  const id = generateId( id_material, DARKLIGHT_NS );
  const timestamp = new Date().toISOString();

  // determine the appropriate ontology class type
  const iri = `<http://cyio.darklight.ai/information-type--${id}>`;
  const insertPredicates = [];
  Object.entries(propValues).forEach((propPair) => {
    if (informationTypePredicateMap.hasOwnProperty(propPair[0])) {
      if (Array.isArray(propPair[1])) {
        for (let value of propPair[1]) {
          insertPredicates.push(informationTypePredicateMap[propPair[0]].binding(iri, value));
        }  
      } else {
        insertPredicates.push(informationTypePredicateMap[propPair[0]].binding(iri, propPair[1]));
      }
    }
  });

  const query = `
  INSERT DATA {
    GRAPH ${iri} {
      ${iri} a <http://csrc.nist.gov/ns/oscal/info-system#InformationType> .
      ${iri} a <http://nist.gov/ns/sp/800-60#InformationType> .
      ${iri} a <http://csrc.nist.gov/ns/oscal/common#Object> .
      ${iri} a <http://darklight.ai/ns/common#Object> .
      ${iri} <http://darklight.ai/ns/common#id> "${id}" .
      ${iri} <http://darklight.ai/ns/common#object_type> "information-type" . 
      ${iri} <http://darklight.ai/ns/common#created> "${timestamp}"^^xsd:dateTime . 
      ${iri} <http://darklight.ai/ns/common#modified> "${timestamp}"^^xsd:dateTime . 
      ${insertPredicates.join(" . \n")}
    }
  }
  `;
  return {iri, id, query}
}
    
export const deleteInformationTypeQuery = (id) => {
  const iri = `http://cyio.darklight.ai/information-type--${id}`;
  return deleteInformationTypeByIriQuery(iri);
}

export const deleteInformationTypeByIriQuery = (iri) => {
  if (!iri.startsWith('<')) iri = `<${iri}>`;
  return `
  DELETE {
    GRAPH ${iri} {
      ?iri ?p ?o
    }
  } WHERE {
    GRAPH ${iri} {
      ?iri a <http://csrc.nist.gov/ns/oscal/info-system#InformationType> .
      ?iri ?p ?o
    }
  }
  `
}

export const deleteMultipleInformationTypesQuery = (ids) =>{
  const values = ids ? (ids.map((id) => `"${id}"`).join(' ')) : "";
  return `
  DELETE {
    GRAPH ?g {
      ?iri ?p ?o
    }
  } WHERE {
    GRAPH ?g {
      ?iri a <http://csrc.nist.gov/ns/oscal/info-system#InformationType> .
      ?iri <http://darklight.ai/ns/common#id> ?id .
      ?iri ?p ?o .
      VALUES ?id {${values}}
    }
  }
  `
}

export const attachToInformationTypeQuery = (id, field, itemIris) => {
  if (!informationTypePredicateMap.hasOwnProperty(field)) return null;
  const iri = `<http://cyio.darklight.ai/information-type--${id}>`;
  const predicate = informationTypePredicateMap[field].predicate;

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
    informationTypePredicateMap, 
    '<http://csrc.nist.gov/ns/oscal/info-system#InformationType>'
  );
}

export const detachFromInformationTypeQuery = (id, field, itemIris) => {
  if (!informationTypePredicateMap.hasOwnProperty(field)) return null;
  const iri = `<http://cyio.darklight.ai/information-type--${id}>`;
  const predicate = informationTypePredicateMap[field].predicate;

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
    informationTypePredicateMap, 
    '<http://csrc.nist.gov/ns/oscal/info-system#InformationType>'
  );
}

// Query Builders - Impact Definition
export const selectImpactDefinitionQuery = (id, select) => {
  return selectImpactDefinitionByIriQuery(`http://cyio.darklight.ai/impact-definition--${id}`, select);
}

export const selectImpactDefinitionByIriQuery = (iri, select) => {
  if (!iri.startsWith('<')) iri = `<${iri}>`;
  if (select === undefined || select === null) select = Object.keys(impactDefinitionPredicateMap);

  // this is needed to assist in the determination of the type of the data source
  if (!select.includes('id')) select.push('id');
  if (!select.includes('object_type')) select.push('object_type');

  const { selectionClause, predicates } = buildSelectVariables(impactDefinitionPredicateMap, select);
  return `
  SELECT ?iri ${selectionClause}
  FROM <tag:stardog:api:context:local>
  WHERE {
    BIND(${iri} AS ?iri)
    ?iri a <http://csrc.nist.gov/ns/oscal/info-system#ImpactDefinition> .
    ${predicates}
  }`
}

export const selectAllImpactDefinitionsQuery = (select, args, parent) => {
  let constraintClause = '';
  if (select === undefined || select === null) select = Object.keys(impactDefinitionPredicateMap);
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
  const { selectionClause, predicates } = buildSelectVariables(impactDefinitionPredicateMap, select);

  return `
  SELECT DISTINCT ?iri ${selectionClause} 
  FROM <tag:stardog:api:context:local>
  WHERE {
    ?iri a <http://csrc.nist.gov/ns/oscal/info-system#ImpactDefinition> . 
    ${predicates}
    ${constraintClause}
  }
  `
}

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
      ${iri} a <http://csrc.nist.gov/ns/oscal/info-system#ImpactDefinition> .
      ${iri} a <http://nist.gov/ns/sp/800-60#InformationDefinition> .
      ${iri} a <http://csrc.nist.gov/ns/oscal/common#ComplexDatatype> .
      ${iri} a <http://darklight.ai/ns/common#ComplexDatatype> .
      ${iri} <http://darklight.ai/ns/common#id> "${id}" .
      ${iri} <http://darklight.ai/ns/common#object_type> "impact-definition" . 
      ${insertPredicates.join(" . \n")}
    }
  }
  `;
  return {iri, id, query}
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
      ?iri a <http://csrc.nist.gov/ns/oscal/info-system#ImpactDefinition> .
      ?iri ?p ?o
    }
  }
  `
}

export const deleteMultipleImpactDefinitionsQuery = (ids) =>{
  const values = ids ? (ids.map((id) => `"${id}"`).join(' ')) : "";
  return `
  DELETE {
    GRAPH ?g {
      ?iri ?p ?o
    }
  } WHERE {
    GRAPH ?g {
      ?iri a <http://csrc.nist.gov/ns/oscal/info-system#ImpactDefinition> .
      ?iri <http://darklight.ai/ns/common#id> ?id .
      ?iri ?p ?o .
      VALUES ?id {${values}}
    }
  }
  `
}

export const attachToImpactDefinitionQuery = (id, field, itemIris) => {
  if (!impactDefinitionPredicateMap.hasOwnProperty(field)) return null;
  const iri = `<http://cyio.darklight.ai/impact-definition--${id}>`;
  const predicate = impactDefinitionPredicateMap[field].predicate;

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
    impactDefinitionPredicateMap, 
    '<http://csrc.nist.gov/ns/oscal/info-system#ImpactDefinition>'
  );
}

export const detachFromImpactDefinitionQuery = (id, field, itemIris) => {
  if (!impactDefinitionPredicateMap.hasOwnProperty(field)) return null;
  const iri = `<http://cyio.darklight.ai/impact-definition--${id}>`;
  const predicate = impactDefinitionPredicateMap[field].predicate;

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
    impactDefinitionPredicateMap, 
    '<http://csrc.nist.gov/ns/oscal/info-system#ImpactDefinition>'
  );
}


// Query Builders - Categorization
export const selectCategorizationQuery = (id, select) => {
  return selectCategorizationByIriQuery(`http://cyio.darklight.ai/categorization--${id}`, select);
}

export const selectCategorizationByIriQuery = (iri, select) => {
  if (!iri.startsWith('<')) iri = `<${iri}>`;
  if (select === undefined || select === null) select = Object.keys(categorizationPredicateMap);

  // this is needed to assist in the determination of the type of the data source
  if (!select.includes('id')) select.push('id');
  if (!select.includes('object_type')) select.push('object_type');
  if (!select.includes('catalog')) select.push('catalog');

  const { selectionClause, predicates } = buildSelectVariables(categorizationPredicateMap, select);
  return `
  SELECT ?iri ${selectionClause}
  FROM <tag:stardog:api:context:local>
  WHERE {
    BIND(${iri} AS ?iri)
    ?iri a <http://csrc.nist.gov/ns/oscal/info-system#Categorization> .
    ${predicates}
  }`
}

export const selectAllCategorizationsQuery = (select, args, parent) => {
  let constraintClause = '';
  if (select === undefined || select === null) select = Object.keys(categorizationPredicateMap);
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
  const { selectionClause, predicates } = buildSelectVariables(categorizationPredicateMap, select);

  return `
  SELECT DISTINCT ?iri ${selectionClause} 
  FROM <tag:stardog:api:context:local>
  WHERE {
    ?iri a <http://csrc.nist.gov/ns/oscal/info-system#Categorization> . 
    ${predicates}
    ${constraintClause}
  }
  `
}

export const insertCategorizationQuery = (propValues) => {
  const id = generateId( );
  const timestamp = new Date().toISOString();

  // determine the appropriate ontology class type
  const iri = `<http://cyio.darklight.ai/categorization--${id}>`;
  const insertPredicates = [];
  Object.entries(propValues).forEach((propPair) => {
    if (categorizationPredicateMap.hasOwnProperty(propPair[0])) {
      if (Array.isArray(propPair[1])) {
        for (let value of propPair[1]) {
          if (categorizationPredicateMap[propPair[0]].hasOwnProperty('ref_binding')) {
            insertPredicates.push(categorizationPredicateMap[propPair[0]].ref_binding(iri, value));
          } else {
          insertPredicates.push(categorizationPredicateMap[propPair[0]].binding(iri, value));
          }
        }  
      } else {
        if (categorizationPredicateMap[propPair[0]].hasOwnProperty('ref_binding')) {
          insertPredicates.push(categorizationPredicateMap[propPair[0]].ref_binding(iri, propPair[1]));
        } else {
          insertPredicates.push(categorizationPredicateMap[propPair[0]].binding(iri, propPair[1]));
        }
      }
    }
  });

  const query = `
  INSERT DATA {
    GRAPH ${iri} {
      ${iri} a <http://csrc.nist.gov/ns/oscal/info-system#Categorization> .
      ${iri} a <http://csrc.nist.gov/ns/oscal/common#ComplexDatatype> .
      ${iri} a <http://darklight.ai/ns/common#ComplexDatatype> .
      ${iri} <http://darklight.ai/ns/common#id> "${id}" .
      ${iri} <http://darklight.ai/ns/common#object_type> "categorization" . 
      ${insertPredicates.join(" . \n")}
    }
  }
  `;
  return {iri, id, query}
}
    
export const deleteCategorizationQuery = (id) => {
  const iri = `http://cyio.darklight.ai/categorization--${id}`;
  return deleteCategorizationByIriQuery(iri);
}

export const deleteCategorizationByIriQuery = (iri) => {
  if (!iri.startsWith('<')) iri = `<${iri}>`;
  return `
  DELETE {
    GRAPH ${iri} {
      ?iri ?p ?o
    }
  } WHERE {
    GRAPH ${iri} {
      ?iri a <http://csrc.nist.gov/ns/oscal/info-system#Categorization> .
      ?iri ?p ?o
    }
  }
  `
}

export const deleteMultipleCategorizationsQuery = (ids) =>{
  const values = ids ? (ids.map((id) => `"${id}"`).join(' ')) : "";
  return `
  DELETE {
    GRAPH ?g {
      ?iri ?p ?o
    }
  } WHERE {
    GRAPH ?g {
      ?iri a <http://csrc.nist.gov/ns/oscal/info-system#Categorization> .
      ?iri <http://darklight.ai/ns/common#id> ?id .
      ?iri ?p ?o .
      VALUES ?id {${values}}
    }
  }
  `
}

export const attachToCategorizationQuery = (id, field, itemIris) => {
  if (!categorizationPredicateMap.hasOwnProperty(field)) return null;
  const iri = `<http://cyio.darklight.ai/categorization--${id}>`;
  const predicate = categorizationPredicateMap[field].predicate;

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
    categorizationPredicateMap, 
    '<http://csrc.nist.gov/ns/oscal/info-system#Categorization>'
  );
}

export const detachFromCategorizationQuery = (id, field, itemIris) => {
  if (!categorizationPredicateMap.hasOwnProperty(field)) return null;
  const iri = `<http://cyio.darklight.ai/categorization--${id}>`;
  const predicate = categorizationPredicateMap[field].predicate;

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
    categorizationPredicateMap, 
    '<http://csrc.nist.gov/ns/oscal/info-system#Categorization>'
  );
}


// Predicate maps
export const informationTypePredicateMap = {
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
  description: {
    predicate: "<http://csrc.nist.gov/ns/oscal/common#description>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"@en-US`: null, this.predicate, "description");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  categorizations: {
    predicate: "<http://csrc.nist.gov/ns/oscal/info-system#categorizations>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "categorizations");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  confidentiality_impact: {
    predicate: "<http://csrc.nist.gov/ns/oscal/info-system#confidentiality_impact>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "confidentiality_impact");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
	confidentiality_base_impact: {
    predicate: "<http://csrc.nist.gov/ns/oscal/info-system#confidentiality_impact>/<http://csrc.nist.gov/ns/oscal/info-system#base_impact>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "confidentiality_base_impact");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
	},
	confidentiality_selected_impact: {
    predicate: "<http://csrc.nist.gov/ns/oscal/info-system#confidentiality_impact>/<http://csrc.nist.gov/ns/oscal/info-system#selected_impact>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "confidentiality_selected_impact");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
	},
	confidentiality_adjustment_justification: {
    predicate: "<http://csrc.nist.gov/ns/oscal/info-system#confidentiality_impact>/<http://csrc.nist.gov/ns/oscal/info-system#adjustment_justification>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"@en-US`: null, this.predicate, "confidentiality_adjustment_justification");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
	},
  integrity_impact: {
    predicate: "<http://csrc.nist.gov/ns/oscal/info-system#integrity_impact>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "integrity_impact");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
	integrity_base_impact: {
    predicate: "<http://csrc.nist.gov/ns/oscal/info-system#integrity_impact>/<http://csrc.nist.gov/ns/oscal/info-system#base_impact>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "integrity_base_impact");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
	},
	integrity_selected_impact: {
    predicate: "<http://csrc.nist.gov/ns/oscal/info-system#integrity_impact>/<http://csrc.nist.gov/ns/oscal/info-system#selected_impact>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "integrity_selected_impact");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
	},
	integrity_adjustment_justification: {
    predicate: "<http://csrc.nist.gov/ns/oscal/info-system#integrity_impact>/<http://csrc.nist.gov/ns/oscal/info-system#adjustment_justification>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"@en-US`: null, this.predicate, "integrity_adjustment_justification");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
	},
  availability_impact: {
    predicate: "<http://csrc.nist.gov/ns/oscal/info-system#availability_impact>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "availability_impact");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
	availability_base_impact: {
    predicate: "<http://csrc.nist.gov/ns/oscal/info-system#availability_impact>/<http://csrc.nist.gov/ns/oscal/info-system#base_impact>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "availability_base_impact");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
	},
	availability_selected_impact: {
    predicate: "<http://csrc.nist.gov/ns/oscal/info-system#availability_impact>/<http://csrc.nist.gov/ns/oscal/info-system#selected_impact>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "availability_selected_impact");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
	},
	availability_adjustment_justification: {
    predicate: "<http://csrc.nist.gov/ns/oscal/info-system#availability_impact>/<http://csrc.nist.gov/ns/oscal/info-system#adjustment_justification>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"@en-US`: null, this.predicate, "availability_adjustment_justification");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
	},
	identifier: {
    predicate: "<http://nist.gov/ns/sp800-60#identifier>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "identifier");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
	},
	category: {
    predicate: "<http://nist.gov/ns/sp800-60#category>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "category");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
	},
	system: {
    predicate: "<http://nist.gov/ns/sp800-60#system>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:anyURI`: null, this.predicate, "system");},
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
	base_impact: {
    predicate: "<http://nist.gov/ns/sp800-60#base_impact>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "base_impact");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
	},
	selected_impact: {
    predicate: "<http://csrc.nist.gov/ns/oscal/info-system#selected_impact>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "selected_impact");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
	},
	adjustment_justification: {
    predicate: "<http://csrc.nist.gov/ns/oscal/info-system#adjustment_justification>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"@en-US`: null, this.predicate, "adjustment_justification");},
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
	identifier: {
    predicate: "<http://nist.gov/ns/sp800-60#identifier>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "recommendation");},
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

export const categorizationPredicateMap = {
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
	catalog: {
    predicate: "<http://csrc.nist.gov/ns/oscal/info-system#system_catalog>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "catalog");},
    ref_binding: function (iri, value) { return parameterizePredicate(iri, value ? `<http://cyio.darklight.ai/information-type-catalog--${value}>`: null, this.predicate, "catalog");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
	},
	system: {
    predicate: "<http://nist.gov/ns/sp800-60#system>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:anyURI`: null, this.predicate, "system");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
	},
	information_type: {
    predicate: "<http://csrc.nist.gov/ns/oscal/info-system#information_type>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "information_type");},
    ref_binding: function (iri, value) { return parameterizePredicate(iri, value ? `<http://cyio.darklight.ai/information-type--${value}>`: null, this.predicate, "information_type");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
	},
};


// Serialization schema
export const singularizeInformationTypeSchema = { 
  singularizeVariables: {
    "": false, // so there is an object as the root instead of an array
    "id": true,
    "iri": true,
    "object_type": true,
    "entity_type": true,
    "created": true,
    "modified": true,
    "display_name": true,
		"title": true,
    "description": true,
    "identifier": true,
    "system": true,
    "category": true,
		"confidentiality_impact": true,
		"confidentiality_base_impact": true,
		"confidentiality_selected_impact": true,
		"confidentiality_adjustment_justification": true,
		"integrity_impact": true,
		"integrity_base_impact": true,
		"integrity_selected_impact": true,
		"integrity_adjustment_justification": true,
		"availability_impact": true,
		"availability_base_impact": true,
		"availability_selected_impact": true,
		"availability_adjustment_justification": true,
  }
};

export const singularizeImpactDefinitionSchema = { 
  singularizeVariables: {
    "": false, // so there is an object as the root instead of an array
    "id": true,
    "iri": true,
    "object_type": true,
    "entity_type": true,
		"base_impact": true,
		"selected_impact": true,
		"adjustment_justification": true,
    "explanation": true,
    "recommendation": true,
  }
};

export const singularizeCategorizationSchema = { 
  singularizeVariables: {
    "": false, // so there is an object as the root instead of an array
    "id": true,
    "iri": true,
    "object_type": true,
    "entity_type": true,
    "catalog": true,
    "system": true,
    "information_type": true,
  }
};
