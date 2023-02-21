import { UserInputError } from 'apollo-server-errors';
import { 
  optionalizePredicate, 
  parameterizePredicate, 
  buildSelectVariables, 
  attachQuery,
  detachQuery,
  generateId, 
  DARKLIGHT_NS,
} from '../../../utils.js';
  
  // Reducer Selection
export function getReducer(type) {
  switch (type) {
    case 'INFORMATION-TYPE':
      return informationTypeReducer;
		case 'IMPACT-LEVEL':
			return impactLevelReducer;
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
			...(item.title && { title: item.title }),
			...(item.description && { description: item.description }),
			// prefetched 
			...(item.confidentiality_base_impact_level && { confidentiality_base_impact_level: item.confidentiality_base_impact_level }),
			...(item.confidentiality_selected_impact_level && { confidentiality_selected_impact_level: item.confidentiality_selected_impact_level }),
			...(item.confidentiality_adjustment_justification && { confidentiality_adjustment_justification: item.confidentiality_adjustment_justification }),
			...(item.integrity_base_impact_level && { integrity_base_impact_level: item.integrity_base_impact_level }),
			...(item.integrity_selected_impact_level && { integrity_selected_impact_level: item.integrity_selected_impact_level }),
			...(item.integrity_adjustment_justification && { integrity_adjustment_justification: item.integrity_adjustment_justification }),
			...(item.availability_base_impact_level && { availability_base_impact_level: item.availability_base_impact_level }),
			...(item.availability_selected_impact_level && { availability_selected_impact_level: item.availability_selected_impact_level }),
			...(item.availability_adjustment_justification && { availability_adjustment_justification: item.availability_adjustment_justification }),
      // hints for field-level resolver queries
      ...(item.categorizations && { categorizations_iris: item.categorizations }),
      ...(item.confidentiality_impact && { confidentiality_impact_iri: item.confidentiality_impact }),
      ...(item.integrity_impact && { integrity_impact_iri: item.integrity_impact }),
      ...(item.availability_impact && { availability_impact_iri: item.availability_impact }),
      ...(item.labels && { labels_iris: item.labels }),
      ...(item.links && { links_iris: item.links }),
      ...(item.remarks && { remarks_iris: item.remarks }),
			...(item.relationships && { relationships: item.relationships }),
  }
};
const impactLevelReducer = (item) => {
  // if no object type was returned, compute the type from the IRI
  if (item.object_type === undefined) {
      if (item.entity_type !== undefined) item.object_type = item.entity_type;
      if (item.iri.includes('information-level')) item.object_type = 'information-level';
  }

  return {
      iri: item.iri,
      id: item.id,
      ...(item.object_type && { entity_type: item.object_type }),
      ...(item.created && { created: item.created }),
      ...(item.modified && { modified: item.modified }),
			...(item.base_impact_level && { base_impact_level: item.base_impact_level }),
			...(item.selected_impact_level && { selected_impact_level: item.selected_impact_level }),
			...(item.adjustment_justification && { adjustment_justification: item.adjustment_justification }),
      // hints for field-level resolver queries
      ...(item.labels && { labels_iris: item.labels }),
      ...(item.links && { links_iris: item.links }),
      ...(item.remarks && { remarks_iris: item.remarks }),
			...(item.relationships && { relationships: item.relationships }),
		}
};
  

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
  const iri = `<http://cyio.darklight.ai/information-type--${id}>`;
  if (!informationTypePredicateMap.hasOwnProperty(field)) return null;
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

  return attachQuery(iri, statements, informationTypePredicateMap, '<http://csrc.nist.gov/ns/oscal/info-system#InformationType>');
}

export const detachFromInformationTypeQuery = (id, field, itemIris) => {
  const iri = `<http://cyio.darklight.ai/information-type--${id}>`;
  if (!informationTypePredicateMap.hasOwnProperty(field)) return null;
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

  return detachQuery(iri, statements, informationTypePredicateMap, '<http://csrc.nist.gov/ns/oscal/info-system#InformationType>');
}

// Query Builders - Impact Level
export const selectImpactLevelQuery = (id, select) => {
  return selectImpactLevelByIriQuery(`http://cyio.darklight.ai/impact-level--${id}`, select);
}

export const selectImpactLevelByIriQuery = (iri, select) => {
  if (!iri.startsWith('<')) iri = `<${iri}>`;
  if (select === undefined || select === null) select = Object.keys(impactLevelPredicateMap);

  // this is needed to assist in the determination of the type of the data source
  if (!select.includes('id')) select.push('id');
  if (!select.includes('object_type')) select.push('object_type');

  const { selectionClause, predicates } = buildSelectVariables(impactLevelPredicateMap, select);
  return `
  SELECT ?iri ${selectionClause}
  FROM <tag:stardog:api:context:local>
  WHERE {
    BIND(${iri} AS ?iri)
    ?iri a <http://csrc.nist.gov/ns/oscal/info-system#ImpactLevel> .
    ${predicates}
  }`
}

export const selectAllImpactLevelsQuery = (select, args, parent) => {
  let constraintClause = '';
  if (select === undefined || select === null) select = Object.keys(impactLevelPredicateMap);
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
  const { selectionClause, predicates } = buildSelectVariables(impactLevelPredicateMap, select);

  return `
  SELECT DISTINCT ?iri ${selectionClause} 
  FROM <tag:stardog:api:context:local>
  WHERE {
    ?iri a <http://csrc.nist.gov/ns/oscal/info-system#ImpactLevel> . 
    ${predicates}
    ${constraintClause}
  }
  `
}

export const insertImpactLevelQuery = (propValues) => {
  const id = generateId( );
  const timestamp = new Date().toISOString();

  // determine the appropriate ontology class type
  const iri = `<http://cyio.darklight.ai/impact-level--${id}>`;
  const insertPredicates = [];
  Object.entries(propValues).forEach((propPair) => {
    if (impactLevelPredicateMap.hasOwnProperty(propPair[0])) {
      if (Array.isArray(propPair[1])) {
        for (let value of propPair[1]) {
          insertPredicates.push(impactLevelPredicateMap[propPair[0]].binding(iri, value));
        }  
      } else {
        insertPredicates.push(impactLevelPredicateMap[propPair[0]].binding(iri, propPair[1]));
      }
    }
  });

  const query = `
  INSERT DATA {
    GRAPH ${iri} {
      ${iri} a <http://csrc.nist.gov/ns/oscal/info-system#ImpactLevel> .
      ${iri} a <http://csrc.nist.gov/ns/oscal/common#Object> .
      ${iri} a <http://darklight.ai/ns/common#Object> .
      ${iri} <http://darklight.ai/ns/common#id> "${id}" .
      ${iri} <http://darklight.ai/ns/common#object_type> "information-level" . 
      ${iri} <http://darklight.ai/ns/common#created> "${timestamp}"^^xsd:dateTime . 
      ${iri} <http://darklight.ai/ns/common#modified> "${timestamp}"^^xsd:dateTime . 
      ${insertPredicates.join(" . \n")}
    }
  }
  `;
  return {iri, id, query}
}
    
export const deleteImpactLevelQuery = (id) => {
  const iri = `http://cyio.darklight.ai/impact-level--${id}`;
  return deleteImpactLevelByIriQuery(iri);
}

export const deleteImpactLevelByIriQuery = (iri) => {
  if (!iri.startsWith('<')) iri = `<${iri}>`;
  return `
  DELETE {
    GRAPH ${iri} {
      ?iri ?p ?o
    }
  } WHERE {
    GRAPH ${iri} {
      ?iri a <http://csrc.nist.gov/ns/oscal/info-system#ImpactLevel> .
      ?iri ?p ?o
    }
  }
  `
}

export const deleteMultipleImpactLevelsQuery = (ids) =>{
  const values = ids ? (ids.map((id) => `"${id}"`).join(' ')) : "";
  return `
  DELETE {
    GRAPH ?g {
      ?iri ?p ?o
    }
  } WHERE {
    GRAPH ?g {
      ?iri a <http://csrc.nist.gov/ns/oscal/info-system#ImpactLevel> .
      ?iri <http://darklight.ai/ns/common#id> ?id .
      ?iri ?p ?o .
      VALUES ?id {${values}}
    }
  }
  `
}

export const attachToImpactLevelQuery = (id, field, itemIris) => {
  const iri = `<http://cyio.darklight.ai/impact-level--${id}>`;
  if (!impactLevelPredicateMap.hasOwnProperty(field)) return null;
  const predicate = impactLevelPredicateMap[field].predicate;
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

  return attachQuery(iri, statements, impactLevelPredicateMap, '<http://csrc.nist.gov/ns/oscal/info-system#ImpactLevel>');
}

export const detachFromImpactLevelQuery = (id, field, itemIris) => {
  const iri = `<http://cyio.darklight.ai/impact-level--${id}>`;
  if (!impactLevelPredicateMap.hasOwnProperty(field)) return null;
  const predicate = impactLevelPredicateMap[field].predicate;
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

  return detachQuery(iri, statements, impactLevelPredicateMap, '<http://csrc.nist.gov/ns/oscal/info-system#ImpactLevel>');
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
	confidentiality_base_impact_level: {
    predicate: "<http://csrc.nist.gov/ns/oscal/info-system#confidentiality_impact>/<http://csrc.nist.gov/ns/oscal/info-system#base_impact_level>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "confidentiality_base_impact_level");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
	},
	confidentiality_selected_impact_level: {
    predicate: "<http://csrc.nist.gov/ns/oscal/info-system#confidentiality_impact>/<http://csrc.nist.gov/ns/oscal/info-system#selected_impact_level>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "confidentiality_selected_impact_level");},
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
	integrity_base_impact_level: {
    predicate: "<http://csrc.nist.gov/ns/oscal/info-system#integrity_impact>/<http://csrc.nist.gov/ns/oscal/info-system#base_impact_level>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "integrity_base_impact_level");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
	},
	integrity_selected_impact_level: {
    predicate: "<http://csrc.nist.gov/ns/oscal/info-system#integrity_impact>/<http://csrc.nist.gov/ns/oscal/info-system#selected_impact_level>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "integrity_selected_impact_level");},
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
	availability_base_impact_level: {
    predicate: "<http://csrc.nist.gov/ns/oscal/info-system#availability_impact>/<http://csrc.nist.gov/ns/oscal/info-system#base_impact_level>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "availability_base_impact_level");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
	},
	availability_selected_impact_level: {
    predicate: "<http://csrc.nist.gov/ns/oscal/info-system#availability_impact>/<http://csrc.nist.gov/ns/oscal/info-system#selected_impact_level>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "availability_selected_impact_level");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
	},
	availability_adjustment_justification: {
    predicate: "<http://csrc.nist.gov/ns/oscal/info-system#availability_impact>/<http://csrc.nist.gov/ns/oscal/info-system#adjustment_justification>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"@en-US`: null, this.predicate, "availability_adjustment_justification");},
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

export const impactLevelPredicateMap = {
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
	base_impact_level: {
    predicate: "<http://csrc.nist.gov/ns/oscal/info-system#base_impact_level>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "base_impact_level");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
	},
	selected_impact_level: {
    predicate: "<http://csrc.nist.gov/ns/oscal/info-system#selected_impact_level>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"`: null, this.predicate, "selected_impact_level");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
	},
	adjustment_justification: {
    predicate: "<http://csrc.nist.gov/ns/oscal/info-system#adjustment_justification>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"@en-US`: null, this.predicate, "adjustment_justification");},
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
		"title": true,
    "description": true,
		"confidentiality_impact": true,
		"confidentiality_base_impact_level": true,
		"confidentiality_selected_impact_level": true,
		"confidentiality_adjustment_justification": true,
		"integrity_impact": true,
		"integrity_base_impact_level": true,
		"integrity_selected_impact_level": true,
		"integrity_adjustment_justification": true,
		"availability_impact": true,
		"availability_base_impact_level": true,
		"availability_selected_impact_level": true,
		"availability_adjustment_justification": true,
  }
};

export const singularizeImpactLevelSchema = { 
  singularizeVariables: {
    "": false, // so there is an object as the root instead of an array
    "id": true,
    "iri": true,
    "object_type": true,
    "entity_type": true,
    "created": true,
    "modified": true,
		"base_impact_level": true,
		"selected_impact_level": true,
		"adjustment_justification": true,
  }
};
