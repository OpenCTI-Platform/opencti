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
import { informationTypePredicateMap } from './informationType.js';
  
  // Reducer Selection
export function getReducer(type) {
  switch (type) {
    case 'INFORMATION-TYPE-CATALOG':
      return informationTypeCatalogReducer;
    default:
      throw new UserInputError(`Unsupported reducer type ' ${type}'`)
  }
}
  
//
// Reducers
//
const informationTypeCatalogReducer = (item) => {
  // if no object type was returned, compute the type from the IRI
  if (item.object_type === undefined) {
      if (item.entity_type !== undefined) item.object_type = item.entity_type;
      if (item.iri.includes('information-type-catalog')) item.object_type = 'information-type-catalog';
  }

  return {
      iri: item.iri,
      id: item.id,
      ...(item.object_type && { entity_type: item.object_type }),
      ...(item.created && { created: item.created }),
      ...(item.modified && { modified: item.modified }),
      ...(item.title && { title: item.title }),
      ...(item.description && { description: item.description }),
      ...(item.system && { system: item.system }),
      // hints for field-level resolver queries
      ...(item.entries && { entries_iri: item.entries }),
  }
}

// Utility
export const getInformationTypeCatalogIri = (id) => {
  return `<http://cyio.darklight.ai/information-type-catalog--${id}>`;
}
  
// Query Builders
export const insertInformationTypeCatalogQuery = (propValues) => {
  const id_material = {
    ...(propValues.system && {"system": propValues.system}),
    ...(propValues.title && {"title": propValues.title}),
  } ;
  const id = generateId( id_material, DARKLIGHT_NS );
  const timestamp = new Date().toISOString();

  // determine the appropriate ontology class type
  const iri = `<http://cyio.darklight.ai/information-type-catalog--${id}>`;
  const insertPredicates = [];
  Object.entries(propValues).forEach((propPair) => {
    if (informationTypeCatalogPredicateMap.hasOwnProperty(propPair[0])) {
      if (Array.isArray(propPair[1])) {
        for (let value of propPair[1]) {
          insertPredicates.push(informationTypeCatalogPredicateMap[propPair[0]].binding(iri, value));
        }  
      } else {
        insertPredicates.push(informationTypeCatalogPredicateMap[propPair[0]].binding(iri, propPair[1]));
      }
    }
  });

  const query = `
  INSERT DATA {
    GRAPH ${iri} {
      ${iri} a <http://nist.gov/ns/sp800-60#InformationTypeCatalog> .
      ${iri} a <http://darklight.ai/ns/common#Object> .
      ${iri} <http://darklight.ai/ns/common#id> "${id}" .
      ${iri} <http://darklight.ai/ns/common#object_type> "information-type-catalog" . 
      ${iri} <http://darklight.ai/ns/common#created> "${timestamp}"^^xsd:dateTime . 
      ${iri} <http://darklight.ai/ns/common#modified> "${timestamp}"^^xsd:dateTime . 
      ${insertPredicates.join(" . \n")}
    }
  }
  `;
  return {iri, id, query}
}
  
export const selectInformationTypeCatalogQuery = (id, select) => {
  return selectInformationTypeCatalogByIriQuery(`http://cyio.darklight.ai/information-type-catalog--${id}`, select);
}

export const selectInformationTypeCatalogByIriQuery = (iri, select) => {
  if (!iri.startsWith('<')) iri = `<${iri}>`;
  if (select === undefined || select === null) select = Object.keys(informationTypeCatalogPredicateMap);

  // this is needed to assist in the determination of the type of the data source
  if (!select.includes('id')) select.push('id');
  if (!select.includes('object_type')) select.push('object_type');
  if (!select.includes('type')) select.push('type');

  const { selectionClause, predicates } = buildSelectVariables(informationTypeCatalogPredicateMap, select);
  return `
  SELECT ?iri ${selectionClause}
  FROM <tag:stardog:api:context:local>
  WHERE {
    BIND(${iri} AS ?iri)
    ?iri a <http://nist.gov/ns/sp800-60#InformationTypeCatalog> .
    ${predicates}
  }`
}

export const selectAllInformationTypeCatalogsQuery = (select, args, parent) => {
  let constraintClause = '';
  if (select === undefined || select === null) select = Object.keys(informationTypeCatalogPredicateMap);
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

  const { selectionClause, predicates } = buildSelectVariables(informationTypeCatalogPredicateMap, select);

  // add constraint clause to limit to those that are referenced by the specified parent
  if (parent !== undefined && parent.iri !== undefined) {
    // define a constraint to limit retrieval to only those referenced by the parent
    constraintClause = `
    {
      SELECT DISTINCT ?iri
      WHERE {
          <${parent.iri}> a <http://darklight.ai/ns/cyio/system-configuration#SystemConfiguration> ;
          <http://darklight.ai/ns/cyio/system-configuration#information_type_catalogs> ?iri .
      }
    }`;
  }

  return `
  SELECT DISTINCT ?iri ${selectionClause} 
  FROM <tag:stardog:api:context:local>
  WHERE {
    ?iri a <http://nist.gov/ns/sp800-60#InformationTypeCatalog> . 
    ${predicates}
    ${constraintClause}
  }
  `
}

export const deleteInformationTypeCatalogQuery = (id) => {
  const iri = `http://cyio.darklight.ai/information-type-catalog--${id}`;
  return deleteInformationTypeCatalogByIriQuery(iri);
}

export const deleteInformationTypeCatalogByIriQuery = (iri) => {
  if (!iri.startsWith('<')) iri = `<${iri}>`;
  return `
  DELETE {
    GRAPH ${iri} {
      ?iri ?p ?o
    }
  } WHERE {
    GRAPH ${iri} {
      ?iri a <http://nist.gov/ns/sp800-60#InformationTypeCatalog> .
      ?iri ?p ?o
    }
  }
  `
}

export const deleteMultipleInformationTypeCatalogsQuery = (ids) =>{
  const values = ids ? (ids.map((id) => `"${id}"`).join(' ')) : "";
  return `
  DELETE {
    GRAPH ?g {
      ?iri ?p ?o
    }
  } WHERE {
    GRAPH ?g {
      ?iri a <http://nist.gov/ns/sp800-60#InformationTypeCatalog> .
      ?iri <http://darklight.ai/ns/common#id> ?id .
      ?iri ?p ?o .
      VALUES ?id {${values}}
    }
  }
  `
}

export const attachToInformationTypeCatalogQuery = (id, field, itemIris) => {
  const iri = `<http://cyio.darklight.ai/information-type-catalog--${id}>`;
  if (!informationTypeCatalogPredicateMap.hasOwnProperty(field)) return null;
  const predicate = informationTypeCatalogPredicateMap[field].predicate;
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

  return attachQuery(iri, statements, informationTypeCatalogPredicateMap, '<http://nist.gov/ns/sp800-60#InformationTypeCatalog>');
}

export const detachFromInformationTypeCatalogQuery = (id, field, itemIris) => {
  const iri = `<http://cyio.darklight.ai/information-type-catalog--${id}>`;
  if (!informationTypeCatalogPredicateMap.hasOwnProperty(field)) return null;
  const predicate = informationTypeCatalogPredicateMap[field].predicate;
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

  return detachQuery(iri, statements, informationTypeCatalogPredicateMap, '<http://nist.gov/ns/sp800-60#InformationTypeCatalog>');
}

// Retrieves all the categories within a catalog
export const selectCatalogCategoriesQuery = (id) => {
  return selectCatalogCategoriesByIriQuery(`http://cyio.darklight.ai/information-type-catalog--${id}`);
}

export const selectCatalogCategoriesByIriQuery = (iri) => {
  if (!iri.startsWith('<')) iri = `<${iri}>`;
  let select = ['category']

  const { selectionClause, predicates } = buildSelectVariables(informationTypePredicateMap, select);

  return `
  SELECT DISTINCT ${selectionClause}
  FROM <tag:stardog:api:context:local>
  WHERE {
    BIND(${iri} AS ?catalog)
    ?iri a <http://csrc.nist.gov/ns/oscal/info-system#InformationType> .
    ${predicates}
    {
      SELECT DISTINCT ?iri
      WHERE {
        ?catalog a <http://nist.gov/ns/sp800-60#InformationTypeCatalog> ;
        <http://nist.gov/ns/sp800-60#entries> ?iri .
      }
    }
  } ORDER BY ASC(?category)
  `
}

export const selectCatalogCategoryMembersQuery= (id, categoryName, select) => {
  return selectCatalogCategoryMembersByIriQuery(`http://cyio.darklight.ai/information-type-catalog--${id}`, categoryName, select);
}

export const selectCatalogCategoryMembersByIriQuery = (iri, categoryName, select) => {
  if (!iri.startsWith('<')) iri = `<${iri}>`;

  // push predicates that are required to detect that its a catalog's information type
  if (!select.includes('identifier')) select.push('identifier');
  if (!select.includes('category')) select.push('category');
  if (!select.includes('system')) select.push('system');
  if (!select.includes('id')) select.push('id');
  if (!select.includes('object_type')) select.push('object_type');

  const { selectionClause, predicates } = buildSelectVariables(informationTypePredicateMap, select);
  let categoryPredicate = informationTypePredicateMap['category'].predicate;

  return `
  SELECT DISTINCT ?iri ${selectionClause}
  FROM <tag:stardog:api:context:local>
  WHERE {
    BIND(${iri} AS ?catalog)
    ?iri a <http://csrc.nist.gov/ns/oscal/info-system#InformationType> .
    ?iri ${categoryPredicate} "${categoryName}" .
    ${predicates}
    {
      SELECT DISTINCT ?iri
      WHERE {
        ?catalog a <http://nist.gov/ns/sp800-60#InformationTypeCatalog> ;
          <http://nist.gov/ns/sp800-60#entries> ?iri .
      }
    }
  } GROUP BY ?iri ${selectionClause} ORDER BY ASC(?identifier)
  `
}

export const selectCatalogMemberQuery = (id, infoTypeId, select) => {
  return selectCatalogMemberByIriQuery(`http://cyio.darklight.ai/information-type-catalog--${id}`, 
                                       `http://cyio.darklight.ai/information-type--${infoTypeId}`, 
                                       select);
}

export const selectCatalogMemberByIriQuery = (iri, infoTypeIri, select) => {
  if (!iri.startsWith('<')) iri = `<${iri}>`;
  if (!infoTypeIri.startsWith('<')) infoTypeIri = `<${infoTypeIri}>`;

  // push predicates that are required to detect that its a catalog's information type
  if (!select.includes('identifier')) select.push('identifier');
  if (!select.includes('category')) select.push('category');
  if (!select.includes('system')) select.push('system');
  if (!select.includes('id')) select.push('id');
  if (!select.includes('object_type')) select.push('object_type');

  const { selectionClause, predicates } = buildSelectVariables(informationTypePredicateMap, select);
  
  return `
  SELECT DISTINCT ?iri ${selectionClause}
  FROM <tag:stardog:api:context:local>
  WHERE {
    ?iri a <http://csrc.nist.gov/ns/oscal/info-system#InformationType> .
    ${predicates}
    {
      SELECT DISTINCT ?iri
      WHERE {
        BIND(${iri} AS ?catalog)
        BIND (${infoTypeIri} AS ?iri)
        ?catalog a <http://nist.gov/ns/sp800-60#InformationTypeCatalog> ;
          <http://nist.gov/ns/sp800-60#entries> ?iri .
      }
    }
  } GROUP BY ?iri ${selectionClause}
  `
}


// Predicate Maps
export const informationTypeCatalogPredicateMap = {
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
    predicate: "<http://nist.gov/ns/sp800-60#title>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "title");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  description: {
    predicate: "<http://nist.gov/ns/sp800-60#description>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"@en-US` : null,  this.predicate, "description");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  system: {
    predicate: "<http://nist.gov/ns/sp800-60#system>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"^^xsd:anyURI` : null,  this.predicate, "system");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
  entries: {
    predicate: "<http://nist.gov/ns/sp800-60#entries>",
    binding: function (iri, value) { return parameterizePredicate(iri, value ? `"${value}"` : null,  this.predicate, "entries");},
    optional: function (iri, value) { return optionalizePredicate(this.binding(iri, value));},
  },
};

export const singularizeInformationTypeCatalogSchema = { 
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
    "system": true,
  }
};
