import { optionalizePredicate, parameterizePredicate, buildSelectVariables } from '../../utils.js';

// Reducer Selection
export function getReducer(type) {
  switch (type) {
    case 'PRODUCT':
      return productReducer;
    default:
      throw new Error(`Unsupported reducer type ' ${type}'`);
  }
}

//
// Reducers
//
const productReducer = (item) => {
  // if no object type was returned, compute the type from the IRI
  if (item.object_type === undefined) {
    if (item.iri.includes('Software')) item.object_type = 'software';
    if (item.iri.includes('Hardware')) item.object_type = 'hardware';
  }

  // construct the name to be displayed to users
  const display_name = item.name;

  return {
    iri: item.iri,
    id: item.id,
    standard_id: item.id,
    ...(item.object_type && { entity_type: item.object_type }),
    ...(item.name && { name: item.name }),
    ...(item.description && { description: item.description }),
    ...(item.vendor && { vendor: item.vendor }),
    ...(item.version && { version: item.version }),
    ...(item.defanged !== undefined && { defanged: item.defanged }),
    ...(item.cpe_identifier && { cpe_identifier: item.cpe_identifier }),
    ...(item.software_identifier && { software_identifier: item.software_identifier }),
    ...(display_name && { display_name }),
  };
};

// Query Builders
export const countProductsQuery = (args) => {
  let classType =
    '{?iri a <http://docs.oasis-open.org/ns/cti/stix#Software>} UNION {?iri a <http://docs.oasis-open.org/ns/cti/stix#Hardware>}';
  let filter = '';
  if (args !== undefined && args.filters !== undefined) {
    for (const filter of args.filters) {
      if (filter.key === 'object_type') {
        if (filter.values[0] === 'software') classType = '?iri a <http://docs.oasis-open.org/ns/cti/stix#Software>';
        if (filter.values[0] === 'hardware') classType = '?iri a <http://docs.oasis-open.org/ns/cti/stix#Hardware>';
      }
    }
    if ('search' in args) {
      filter = `
    ?iri <http://docs.oasis-open.org/ns/cti#name> ?name .
    FILTER (STRSTARTS(STR(?name), '${args.search}'))`;
    }
  }

  return `
  SELECT DISTINCT (COUNT(?iri) AS ?count)
  FROM <tag:stardog:api:context:local>
  WHERE {
    ${classType} .
    ${filter}
  }
  `;
};

export const selectProductQuery = (id, select) => {
  return selectProductByIriQuery(`http://cti.oasis-open.org/${id}`, select);
};
export const selectSoftwareProductQuery = (id, select) => {
  return selectProductByIriQuery(`http://cti.oasis-open.org/${id}`, select);
};
export const selectHardwareProductQuery = (id, select) => {
  return selectProductByIriQuery(`http://cti.oasis-open.org/${id}`, select);
};

export const selectProductByIriQuery = (iri, select) => {
  if (!iri.startsWith('<')) iri = `<${iri}>`;
  if (select === undefined || select === null) select = Object.keys(productPredicateMap);
  if (!select.includes('id')) select.push('id');
  if (!select.includes('object_type')) select.push('object_type');

  let classType;
  if (iri.includes('hardware--')) classType = 'Hardware';
  if (iri.includes('software--')) classType = 'Software';

  const { selectionClause, predicates } = buildSelectVariables(productPredicateMap, select);
  return `
  SELECT ?iri ${selectionClause}
  FROM <tag:stardog:api:context:local>
  WHERE {
    BIND(${iri} AS ?iri)
    ?iri a <http://docs.oasis-open.org/ns/cti/stix#${classType}> .
    ${predicates}
  }
  `;
};

export const selectAllProducts = (select, args, parent) => {
  const constraintClause = '';
  let orderBy = '';
  let orderMode = '';
  let searchFilter = '';
  let classType =
    '{?iri a <http://docs.oasis-open.org/ns/cti/stix#Software>} UNION {?iri a <http://docs.oasis-open.org/ns/cti/stix#Hardware>}';
  if (select === undefined || select === null) select = Object.keys(productPredicateMap);
  if (select.includes('props')) select = Object.keys(productPredicateMap);
  if (!select.includes('id')) select.push('id');
  if (!select.includes('object_type')) select.push('object_type');

  if (args !== undefined) {
    // add value of filter's key to cause special predicates to be included
    if (args.filters !== undefined) {
      for (const filter of args.filters) {
        if (filter.key === 'object_type') {
          if (filter.values[0] === 'software') classType = '?iri a <http://docs.oasis-open.org/ns/cti/stix#Software>';
          if (filter.values[0] === 'hardware') classType = '?iri a <http://docs.oasis-open.org/ns/cti/stix#Hardware>';
          continue;
        }
        if (!select.includes(filter.key)) select.push(filter.key);
      }
    }

    // add value of orderedBy's key to cause special predicates to be included
    if (args.orderedBy !== undefined) {
      if (!select.includes(args.orderedBy)) select.push(args.orderedBy);
      orderMode = args.orderMode ? args.orderMode.toUpperCase() : 'ASC';
      orderBy = `ORDER BY ${orderMode}(?${args.orderedBy})`;
    }

    // define search filter for the name predicate
    if (args.search !== undefined) {
      searchFilter = `FILTER (STRSTARTS(STR(?name), '${args.search}'))`;
      if (!select.includes('name')) select.push('name');
    }
  }

  // compute the selection clause and predicates
  const { selectionClause, predicates } = buildSelectVariables(productPredicateMap, select);

  return `
  SELECT DISTINCT ?iri ${selectionClause} 
  FROM <tag:stardog:api:context:local>
  WHERE {
    ${classType} .
    ${predicates}
    ${searchFilter}
  } ${orderBy}
  `;
};

// Predicate Map
export const productPredicateMap = {
  id: {
    predicate: '<http://docs.oasis-open.org/ns/cti#id>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'id');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  object_type: {
    predicate: '<http://docs.oasis-open.org/ns/cti#object_type>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'object_type');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  created: {
    predicate: '<http://docs.oasis-open.org/ns/cti#created>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime` : null, this.predicate, 'created');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  modified: {
    predicate: '<http://docs.oasis-open.org/ns/cti#modified>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime` : null, this.predicate, 'modified');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  name: {
    predicate: '<http://docs.oasis-open.org/ns/cti#name>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'name');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  description: {
    predicate: '<http://docs.oasis-open.org/ns/cti#description>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'description');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  vendor: {
    predicate: '<http://docs.oasis-open.org/ns/cti#vendor>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'vendor');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  version: {
    predicate: '<http://docs.oasis-open.org/ns/cti#version>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'version');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  defanged: {
    predicate: '<http://docs.oasis-open.org/ns/cti/stix#defanged>',
    binding(iri, value) {
      return parameterizePredicate(
        iri,
        value !== undefined ? `"${value}"^^xsd:boolean` : null,
        this.predicate,
        'defanged'
      );
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  cpe_identifier: {
    predicate: '<http://docs.oasis-open.org/ns/cti/stix/software#cpe>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'cpe_identifier');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  software_identifier: {
    predicate: '<http://docs.oasis-open.org/ns/cti/stix/software#swid>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'software_identifier');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  critical_software: {
    predicate: '<http://docs.oasis-open.org/ns/cti/stix/ext/ex14028#critical_software>',
    binding(iri, value) {
      return parameterizePredicate(
        iri,
        value !== undefined ? `"${value}"^^xsd:boolean` : null,
        this.predicate,
        'critical_software'
      );
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  software_type: {
    predicate: '<http://docs.oasis-open.org/ns/cti/stix/ext/ex14028#software_type>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'software_type');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
};

export const productSingularizeSchema = {
  singularizeVariables: {
    '': false, // so there is an object as the root instead of an array
    id: true,
    iri: true,
    object_type: true,
    count: true,
    created: true,
    modified: true,
    name: true,
    description: true,
    vendor: true,
    version: true,
    defanged: true,
    cpe_identifier: true,
    software_identifier: true,
    critical_software: true,
    software_type: true,
  },
};
