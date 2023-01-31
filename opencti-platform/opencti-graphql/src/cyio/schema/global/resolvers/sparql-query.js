import {
  byIdClause,
  optionalizePredicate,
  parameterizePredicate,
  buildSelectVariables,
  generateId,
  OASIS_NS,
} from '../../utils.js';

// Reducer Selection
export function getReducer(type) {
  switch (type) {
    case 'ADDRESS':
      return addressReducer;
    case 'EXTERNAL-REFERENCE':
      return externalReferenceReducer;
    case 'LABEL':
      return labelReducer;
    case 'NOTE':
      return noteReducer;
    case 'PHONE-NUMBER':
      return phoneReducer;
    default:
      throw new Error(`Unsupported reducer type ' ${type}'`);
  }
}

//
// Reducers
//
const addressReducer = (item) => {
  // if no object type was returned, compute the type from the IRI
  if (item.object_type === undefined) {
    item.object_type = 'address';
  }

  return {
    id: item.id,
    standard_id: item.id,
    ...(item.object_type && { entity_type: item.object_type }),
    ...(item.address_type && { address_type: item.address_type }),
    ...(item.street_address && { street_address: item.street_address }),
    ...(item.city && { city: item.city }),
    ...(item.administrative_area && { administrative_area: item.administrative_area }),
    ...(item.postal_code && { postal_code: item.postal_code }),
    ...(item.country_code && { country_code: item.country_code }),
  };
};
const externalReferenceReducer = (item) => {
  // if no object type was returned, compute the type from the IRI
  if (item.object_type === undefined) {
    item.object_type = 'external-reference';
  }

  return {
    id: item.id,
    standard_id: item.id,
    ...(item.object_type && { entity_type: item.object_type }),
    ...(item.created && { created: item.created }),
    ...(item.modified && { modified: item.modified }),
    // External Reference
    ...(item.source_name && { source_name: item.source_name }),
    ...(item.description && { description: item.description }),
    ...(item.url && { url: item.url }),
    ...(item.external_id && { external_id: item.external_id }),
    // OSCAL Link
    ...(item.reference_purpose && { reference_purpose: item.reference_purpose }),
    ...(item.media_type && { media_type: item.media_type }),
    ...(item.label_text && { label_text: item.label_text }),
    // HINTS
    ...(item.hashes && { hashes_iri: item.hashes }),
  };
};
const labelReducer = (item) => {
  // if no object type was returned, compute the type from the IRI
  if (item.object_type === undefined) {
    item.object_type = 'label';
  }

  return {
    id: item.id,
    standard_id: item.id,
    ...(item.object_type && { entity_type: item.object_type }),
    ...(item.created && { created: item.created }),
    ...(item.modified && { modified: item.modified }),
    ...(item.name && { name: item.name }),
    ...(item.description && { description: item.description }),
    // Label
    ...(item.color && { color: item.color }),
  };
};
const noteReducer = (item) => {
  // if no object type was returned, compute the type from the IRI
  if (item.object_type === undefined) {
    item.object_type = 'note';
  }

  return {
    id: item.id,
    standard_id: item.id,
    ...(item.object_type && { entity_type: item.object_type }),
    ...(item.created && { created: item.created }),
    ...(item.modified && { modified: item.modified }),
    // Note
    ...(item.abstract && { abstract: item.abstract }),
    ...(item.content && { content: item.content }),
    ...(item.authors && { authors: item.authors }),
    // HINTS
    ...(item.labels && { labels_iri: item.labels }),
  };
};
const phoneReducer = (item) => {
  // if no object type was returned, compute the type from the IRI
  if (item.object_type === undefined) {
    item.object_type = 'telephone-number';
  }

  return {
    id: item.id,
    standard_id: item.id,
    ...(item.object_type && { entity_type: item.object_type }),
    ...(item.usage_type && { usage_type: item.usage_type }),
    ...(item.phone_number && { phone_number: item.phone_number }),
  };
};

//  Predicate Maps
export const addressPredicateMap = {
  id: {
    predicate: '<http://darklight.ai/ns/common#id>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'id');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  object_type: {
    predicate: '<http://darklight.ai/ns/common#object_type>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'object_type');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  address_type: {
    predicate: '<http://csrc.nist.gov/ns/oscal/common#address_type>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'address_type');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  street_address: {
    predicate: '<http://darklight.ai/ns/common#street_address>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'street_address');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  city: {
    predicate: '<http://darklight.ai/ns/common#city>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'city');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  administrative_area: {
    predicate: '<http://darklight.ai/ns/common#administrative_area>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'administrative_area');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  postal_code: {
    predicate: '<http://darklight.ai/ns/common#postal_code>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'postal_code');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  country_code: {
    predicate: '<http://darklight.ai/ns/common#country_code>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'country_code');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
};
export const externalReferencePredicateMap = {
  id: {
    predicate: '<http://darklight.ai/ns/common#id>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'id');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  object_type: {
    predicate: '<http://darklight.ai/ns/common#object_type>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'object_type');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  created: {
    predicate: '<http://darklight.ai/ns/common#created>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime` : null, this.predicate, 'created');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  modified: {
    predicate: '<http://darklight.ai/ns/common#modified>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime` : null, this.predicate, 'modified');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  source_name: {
    predicate: '<http://darklight.ai/ns/common#source_name>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'source_name');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  description: {
    predicate: '<http://darklight.ai/ns/common#description>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'description');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  url: {
    predicate: '<http://darklight.ai/ns/common#url>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"^^xsd:anyURI` : null, this.predicate, 'url');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  hashes: {
    predicate: '<http://darklight.ai/ns/common#hashes>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'hashes');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  external_id: {
    predicate: '<http://darklight.ai/ns/common#external_id>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'external_id');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  reference_purpose: {
    predicate: '<http://csrc.nist.gov/ns/oscal/common#reference_purpose>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'reference_purpose');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  media_type: {
    predicate: '<http://csrc.nist.gov/ns/oscal/common#media_type>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'media_type');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  label_text: {
    predicate: '<http://csrc.nist.gov/ns/oscal/common#label_text>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'label_text');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
};
export const labelPredicateMap = {
  id: {
    predicate: '<http://darklight.ai/ns/common#id>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'id');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  object_type: {
    predicate: '<http://darklight.ai/ns/common#object_type>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'object_type');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  created: {
    predicate: '<http://darklight.ai/ns/common#created>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime` : null, this.predicate, 'created');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  modified: {
    predicate: '<http://darklight.ai/ns/common#modified>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime` : null, this.predicate, 'modified');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  name: {
    predicate: '<http://darklight.ai/ns/common#name>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'name');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  description: {
    predicate: '<http://darklight.ai/ns/common#description>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'description');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  color: {
    predicate: '<http://darklight.ai/ns/common#color>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'color');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
};
export const notePredicateMap = {
  id: {
    predicate: '<http://darklight.ai/ns/common#id>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'id');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  object_type: {
    predicate: '<http://darklight.ai/ns/common#object_type>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'object_type');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  created: {
    predicate: '<http://darklight.ai/ns/common#created>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime` : null, this.predicate, 'created');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  modified: {
    predicate: '<http://darklight.ai/ns/common#modified>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"^^xsd:dateTime` : null, this.predicate, 'modified');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  abstract: {
    predicate: '<http://darklight.ai/ns/common#abstract>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'abstract');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  content: {
    predicate: '<http://darklight.ai/ns/common#content>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'content');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  authors: {
    predicate: '<http://darklight.ai/ns/common#authors>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'authors');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  labels: {
    predicate: '<http://darklight.ai/ns/common#labels>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'labels');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  label_name: {
    predicate: '<http://darklight.ai/ns/common#labels>/<http://darklight.ai/ns/common#name>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'label_name');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
};
export const phoneNumberPredicateMap = {
  id: {
    predicate: '<http://darklight.ai/ns/common#id>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'id');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  object_type: {
    predicate: '<http://darklight.ai/ns/common#object_type>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'object_type');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  usage_type: {
    predicate: '<http://csrc.nist.gov/ns/oscal/common#phone_number_type>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'usage_type');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
  phone_number: {
    predicate: '<http://csrc.nist.gov/ns/oscal/common#phone_number>',
    binding(iri, value) {
      return parameterizePredicate(iri, value ? `"${value}"` : null, this.predicate, 'phone_number');
    },
    optional(iri, value) {
      return optionalizePredicate(this.binding(iri, value));
    },
  },
};

// Address support functions
export const insertAddressQuery = (propValues) => {
  const id_material = {
    ...(propValues.address_type && { address_type: propValues.address_type }),
    ...(propValues.street_address && { street_address: propValues.street_address }),
    ...(propValues.city && { city: propValues.city }),
    ...(propValues.administrative_area && { administrative_area: propValues.administrative_area }),
    ...(propValues.country_code && { country_code: propValues.country_code }),
    ...(propValues.postal_code && { postal_code: propValues.postal_code }),
  };
  const id = generateId(id_material, OASIS_NS);
  const iri = `<http://csrc.nist.gov/ns/oscal/common#Address-${id}>`;
  const insertPredicates = Object.entries(propValues)
    .filter((propPair) => addressPredicateMap.hasOwnProperty(propPair[0]))
    .map((propPair) => addressPredicateMap[propPair[0]].binding(iri, propPair[1]))
    .join('. \n      ');
  const query = `
  INSERT DATA {
    GRAPH ${iri} {
      ${iri} a <http://csrc.nist.gov/ns/oscal/common#Address> .
      ${iri} a <http://csrc.nist.gov/ns/oscal/common#ComplexDatatype> .
      ${iri} a <http://darklight.ai/ns/common#ComplexDatatype> .
      ${iri} <http://darklight.ai/ns/common#id> "${id}" .
      ${iri} <http://darklight.ai/ns/common#object_type> "address" . 
      ${insertPredicates}
    }
  }
  `;
  return { iri, id, query };
};
export const insertAddressesQuery = (addresses) => {
  const graphs = [];
  const addrIris = [];
  addresses.forEach((addr) => {
    const id_material = {
      ...(addr.address_type && { address_type: addr.address_type }),
      ...(addr.street_address && { street_address: addr.street_address }),
      ...(addr.city && { city: addr.city }),
      ...(addr.administrative_area && { administrative_area: addr.administrative_area }),
      ...(addr.country_code && { country_code: addr.country_code }),
      ...(addr.postal_code && { postal_code: addr.postal_code }),
    };
    const id = generateId(id_material, OASIS_NS);
    const insertPredicates = [];
    const iri = `<http://csrc.nist.gov/ns/oscal/common#Address-${id}>`;
    addrIris.push(iri);
    insertPredicates.push(`${iri} a <http://csrc.nist.gov/ns/oscal/common#Address>`);
    insertPredicates.push(`${iri} a <http://csrc.nist.gov/ns/oscal/common#ComplexDatatype>`);
    insertPredicates.push(`${iri} a <http://darklight.ai/ns/common#ComplexDatatype>`);
    insertPredicates.push(`${iri} <http://darklight.ai/ns/common#id> "${id}"`);
    insertPredicates.push(`${iri} <http://darklight.ai/ns/common#object_type> "address"`);
    insertPredicates.push(`${iri} <http://csrc.nist.gov/ns/oscal/common#address_type> "${addr.address_type}"`);
    if (addr.street_address !== undefined && addr.street_address !== null) {
      insertPredicates.push(`${iri} <http://darklight.ai/ns/common#street_address> "${addr.street_address}"`);
    }
    if (addr.city !== undefined && addr.city !== null) {
      insertPredicates.push(`${iri} <http://darklight.ai/ns/common#city> "${addr.city}"`);
    }
    if (addr.administrative_area !== undefined && addr.administrative_area !== null) {
      insertPredicates.push(`${iri} <http://darklight.ai/ns/common#administrative_area> "${addr.administrative_area}"`);
    }
    if (addr.postal_code !== undefined && addr.postal_code !== null) {
      insertPredicates.push(`${iri} <http://darklight.ai/ns/common#postal_code> "${addr.postal_code}"`);
    }
    if (addr.country_code !== undefined && addr.country_code !== null) {
      insertPredicates.push(`${iri} <http://darklight.ai/ns/common#country_code> "${addr.country_code}"`);
    }

    graphs.push(`
  GRAPH ${iri} {
    ${insertPredicates.join('.\n        ')}
  }
    `);
  });
  const query = `
  INSERT DATA {
    ${graphs.join('\n')}
  }`;
  return { addrIris, query };
};
export const selectAddressQuery = (id, select) => {
  return selectAddressByIriQuery(`http://csrc.nist.gov/ns/oscal/common#Address-${id}`, select);
};
export const selectAddressByIriQuery = (iri, select) => {
  if (!iri.startsWith('<')) iri = `<${iri}>`;
  if (select === undefined || select === null) select = Object.keys(addressPredicateMap);
  if (!select.includes('id')) select.push('id');
  const { selectionClause, predicates } = buildSelectVariables(addressPredicateMap, select);
  return `
  SELECT ${selectionClause}
  FROM <tag:stardog:api:context:local>
  WHERE {
    BIND(${iri} AS ?iri)
    ?iri a <http://csrc.nist.gov/ns/oscal/common#Address> .
    ${predicates}
  }
  `;
};
export const selectAllAddresses = (select, args) => {
  if (select === undefined || select === null) select = Object.keys(addressPredicateMap);
  if (!select.includes('id')) select.push('id');

  if (args !== undefined) {
    if (args.filters !== undefined) {
      for (const filter of args.filters) {
        if (!select.includes(filter.key)) select.push(filter.key);
      }
    }

    // add value of orderedBy's key to cause special predicates to be included
    if (args.orderedBy !== undefined) {
      if (!select.includes(args.orderedBy)) select.push(args.orderedBy);
    }
  }

  const { selectionClause, predicates } = buildSelectVariables(addressPredicateMap, select);
  return `
  SELECT DISTINCT ?iri ${selectionClause} 
  FROM <tag:stardog:api:context:local>
  WHERE {
    ?iri a <http://csrc.nist.gov/ns/oscal/common#Address> . 
    ${predicates}
  }
  `;
};
export const deleteAddressQuery = (id) => {
  const iri = `http://csrc.nist.gov/ns/oscal/common#Address-${id}`;
  return deleteAddressByIriQuery(iri);
};
export const deleteAddressByIriQuery = (iri) => {
  return `
  DELETE {
    GRAPH <${iri}> {
      ?iri ?p ?o
    }
  } WHERE {
    GRAPH <${iri}> {
      ?iri a <http://csrc.nist.gov/ns/oscal/common#Address> .
      ?iri ?p ?o
    }
  }
  `;
};
export const attachToAddressQuery = (id, field, itemIris) => {
  const iri = `<http://csrc.nist.gov/ns/oscal/common#Address-${id}>`;
  if (!addressPredicateMap.hasOwnProperty(field)) return null;
  const { predicate } = addressPredicateMap[field];
  let statements;
  if (Array.isArray(itemIris)) {
    statements = itemIris.map((itemIri) => `${iri} ${predicate} ${itemIri}`).join('.\n        ');
  } else {
    statements = `${iri} ${predicate} ${itemIris}`;
  }
  return `
  INSERT DATA {
    GRAPH ${iri} {
      ${statements}
    }
  }
  `;
};
export const detachFromAddressQuery = (id, field, itemIris) => {
  const iri = `<http://csrc.nist.gov/ns/oscal/common#Address-${id}>`;
  if (!addressPredicateMap.hasOwnProperty(field)) return null;
  const { predicate } = addressPredicateMap[field];
  let statements;
  if (Array.isArray(itemIris)) {
    statements = itemIris.map((itemIri) => `${iri} ${predicate} ${itemIri}`).join('.\n        ');
  } else {
    statements = `${iri} ${predicate} ${itemIris}`;
  }
  return `
  DELETE DATA {
    GRAPH ${iri} {
      ${statements}
    }
  }
  `;
};

// Label support functions
export const insertLabelQuery = (propValues) => {
  const id_material = {
    ...(propValues.name && { name: propValues.name }),
  };
  const id = generateId(id_material, OASIS_NS);
  const timestamp = new Date().toISOString();
  const iri = `<http://darklight.ai/ns/common#Label-${id}>`;
  const insertPredicates = Object.entries(propValues)
    .filter((propPair) => labelPredicateMap.hasOwnProperty(propPair[0]))
    .map((propPair) => labelPredicateMap[propPair[0]].binding(iri, propPair[1]))
    .join('. \n      ');
  const query = `
  INSERT DATA {
    GRAPH ${iri} {
      ${iri} a <http://darklight.ai/ns/common#Label> .
      ${iri} a <http://darklight.ai/ns/common#Object> .
      ${iri} <http://darklight.ai/ns/common#id> "${id}".
      ${iri} <http://darklight.ai/ns/common#object_type> "label" . 
      ${iri} <http://darklight.ai/ns/common#created> "${timestamp}"^^xsd:dateTime . 
      ${iri} <http://darklight.ai/ns/common#modified> "${timestamp}"^^xsd:dateTime . 
      ${insertPredicates}
    }
  }
  `;
  return { iri, id, query };
};
export const selectLabelQuery = (id, select) => {
  return selectLabelByIriQuery(`http://darklight.ai/ns/common#Label-${id}`, select);
};
export const selectLabelByIriQuery = (iri, select) => {
  if (!iri.startsWith('<')) iri = `<${iri}>`;
  if (select === undefined || select === null) select = Object.keys(labelPredicateMap);
  const { selectionClause, predicates } = buildSelectVariables(labelPredicateMap, select);
  return `
  SELECT ${selectionClause}
  FROM <tag:stardog:api:context:local>
  WHERE {
    BIND(${iri} AS ?iri)
    ?iri a <http://darklight.ai/ns/common#Label> .
    ${predicates}
  }
  `;
};
export const selectAllLabels = (select, args) => {
  if (select === undefined || select === null) select = Object.keys(labelPredicateMap);
  if (!select.includes('id')) select.push('id');

  if (args !== undefined) {
    if (args.filters !== undefined) {
      for (const filter of args.filters) {
        if (!select.includes(filter.key)) select.push(filter.key);
      }
    }

    // add value of orderedBy's key to cause special predicates to be included
    if (args.orderedBy !== undefined) {
      if (!select.includes(args.orderedBy)) select.push(args.orderedBy);
    }
  }

  const { selectionClause, predicates } = buildSelectVariables(labelPredicateMap, select);
  return `
  SELECT DISTINCT ?iri ${selectionClause} 
  FROM <tag:stardog:api:context:local>
  WHERE {
    ?iri a <http://darklight.ai/ns/common#Label> . 
    ${predicates}
  }
  `;
};
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
  `;
};
export const attachToLabelQuery = (id, field, itemIris) => {
  const iri = `<http://darklight.ai/ns/common#Label-${id}>`;
  if (!labelPredicateMap.hasOwnProperty(field)) return null;
  const { predicate } = labelPredicateMap[field];
  let statements;
  if (Array.isArray(itemIris)) {
    statements = itemIris.map((itemIri) => `${iri} ${predicate} ${itemIri}`).join('.\n        ');
  } else {
    statements = `${iri} ${predicate} ${itemIris}`;
  }
  return `
  INSERT DATA {
    GRAPH ${iri} {
      ${statements}
    }
  }
  `;
};
export const detachFromLabelQuery = (id, field, itemIris) => {
  const iri = `<http://darklight.ai/ns/common#Label-${id}>`;
  if (!labelPredicateMap.hasOwnProperty(field)) return null;
  const { predicate } = labelPredicateMap[field];
  let statements;
  if (Array.isArray(itemIris)) {
    statements = itemIris.map((itemIri) => `${iri} ${predicate} ${itemIri}`).join('.\n        ');
  } else {
    statements = `${iri} ${predicate} ${itemIris}`;
  }
  return `
  DELETE DATA {
    GRAPH ${iri} {
      ${statements}
    }
  }
  `;
};

// External Reference support functions
export const insertExternalReferenceQuery = (propValues) => {
  const id_material = {
    ...(propValues.source_name && { source_name: propValues.source_name }),
    ...(propValues.external_id && { external_id: propValues.external_id }),
    ...(propValues.url && { url: propValues.url }),
  };

  if (propValues.description !== undefined) {
    // escape any newlines
    if (propValues.description.includes('\n')) propValues.description = propValues.description.replace(/\n/g, '\\n');
    if (propValues.description.includes('"')) propValues.description = propValues.description.replace(/\"/g, '\\"');
    if (propValues.description.includes("'")) propValues.description = propValues.description.replace(/\'/g, "\\'");
  }

  const id = generateId(id_material, OASIS_NS);
  const timestamp = new Date().toISOString();
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
      ${iri} <http://darklight.ai/ns/common#id> "${id}".
      ${iri} <http://darklight.ai/ns/common#object_type> "external-reference" . 
      ${iri} <http://darklight.ai/ns/common#created> "${timestamp}"^^xsd:dateTime . 
      ${iri} <http://darklight.ai/ns/common#modified> "${timestamp}"^^xsd:dateTime . 
      ${insertPredicates}
    }
  }
  `;
  return { iri, id, query };
};
export const insertExternalReferencesQuery = (externalReferences) => {
  const graphs = [];
  const extRefIris = [];
  externalReferences.forEach((extRef) => {
    const id_material = {
      ...(extRef.source_name && { source_name: extRef.source_name }),
      ...(extRef.external_id && { external_id: extRef.external_id }),
      ...(extRef.url && { url: extRef.url }),
    };
    const id = generateId(id_material, OASIS_NS);

    if (extRef.description !== undefined) {
      // escape any newlines
      if (extRef.description.includes('\n')) extRef.description = extRef.description.replace(/\n/g, '\\n');
      if (extRef.description.includes('"')) extRef.description = extRef.description.replace(/\"/g, '\\"');
      if (extRef.description.includes("'")) extRef.description = extRef.description.replace(/\'/g, "\\'");
    }

    const insertPredicates = [];
    const iri = `<http://darklight.ai/ns/common#ExternalReference-${id}>`;
    extRefIris.push(iri);
    insertPredicates.push(`${iri} a <http://darklight.ai/ns/common#ExternalReference>`);
    insertPredicates.push(`${iri} a <http://darklight.ai/ns/common#ComplexDatatype>`);
    insertPredicates.push(`${iri} <http://darklight.ai/ns/common#id> "${id}"`);
    insertPredicates.push(`${iri} <http://darklight.ai/ns/common#object_type> "external-reference"`);
    if (extRef.source_name !== undefined && extRef.source_name !== null) {
      insertPredicates.push(`${iri} <http://darklight.ai/ns/common#source_name> "${extRef.source_name}"`);
    }
    if (extRef.description !== undefined && extRef.description !== null) {
      insertPredicates.push(`${iri} <http://darklight.ai/ns/common#description> "${extRef.description}"`);
    }
    if (extRef.external_id !== undefined && extRef.external_id !== null) {
      insertPredicates.push(`${iri} <http://darklight.ai/ns/common#external_id> "${extRef.external_id}"`);
    }
    if (extRef.url !== undefined && extRef.url !== null) {
      insertPredicates.push(`${iri} <http://darklight.ai/ns/common#url> "${extRef.url}"^^xsd:anyURI`);
    }

    graphs.push(`
  GRAPH ${iri} {
    ${insertPredicates.join('.\n        ')}
  }
    `);
  });
  const query = `
  INSERT DATA {
    ${graphs.join('\n')}
  }`;
  return { extRefIris, query };
};
export const selectExternalReferenceQuery = (id, select) => {
  return selectExternalReferenceByIriQuery(`http://darklight.ai/ns/common#ExternalReference-${id}`, select);
};
export const selectExternalReferenceByIriQuery = (iri, select) => {
  if (!iri.startsWith('<')) iri = `<${iri}>`;
  if (select === undefined || select === null) select = Object.keys(externalReferencePredicateMap);
  const { selectionClause, predicates } = buildSelectVariables(externalReferencePredicateMap, select);
  return `
  SELECT ${selectionClause}
  FROM <tag:stardog:api:context:local>
  WHERE {
    BIND(${iri} AS ?iri)
    ?iri a <http://darklight.ai/ns/common#ExternalReference> .
    ${predicates}
  }
  `;
};
export const selectAllExternalReferences = (select, args) => {
  if (select === undefined || select === null) select = Object.keys(externalReferencePredicateMap);
  if (!select.includes('id')) select.push('id');

  if (args !== undefined) {
    if (args.filters !== undefined) {
      for (const filter of args.filters) {
        if (!select.includes(filter.key)) select.push(filter.key);
      }
    }

    // add value of orderedBy's key to cause special predicates to be included
    if (args.orderedBy !== undefined) {
      if (!select.includes(args.orderedBy)) select.push(args.orderedBy);
    }
  }

  const { selectionClause, predicates } = buildSelectVariables(externalReferencePredicateMap, select);
  return `
  SELECT DISTINCT ?iri ${selectionClause} 
  FROM <tag:stardog:api:context:local>
  WHERE {
    ?iri a <http://darklight.ai/ns/common#ExternalReference> . 
    ${predicates}
  }
  `;
};
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
  `;
};
export const attachToExternalReferenceQuery = (id, field, itemIris) => {
  const iri = `<http://darklight.ai/ns/common#ExternalReference-${id}>`;
  if (!externalReferencePredicateMap.hasOwnProperty(field)) return null;
  const { predicate } = externalReferencePredicateMap[field];
  let statements;
  if (Array.isArray(itemIris)) {
    statements = itemIris.map((itemIri) => `${iri} ${predicate} ${itemIri}`).join('.\n        ');
  } else {
    statements = `${iri} ${predicate} ${itemIris}`;
  }
  return `
  INSERT DATA {
    GRAPH ${iri} {
      ${statements}
    }
  }
  `;
};
export const detachFromExternalReferenceQuery = (id, field, itemIris) => {
  const iri = `<http://darklight.ai/ns/common#ExternalReference-${id}>`;
  if (!externalReferencePredicateMap.hasOwnProperty(field)) return null;
  const { predicate } = externalReferencePredicateMap[field];
  let statements;
  if (Array.isArray(itemIris)) {
    statements = itemIris.map((itemIri) => `${iri} ${predicate} ${itemIri}`).join('.\n        ');
  } else {
    statements = `${iri} ${predicate} ${itemIris}`;
  }
  return `
  DELETE DATA {
    GRAPH ${iri} {
      ${statements}
    }
  }
  `;
};

// Note support functions
export const insertNoteQuery = (propValues) => {
  const id_material = {
    ...(propValues.abstract && { abstract: propValues.abstract }),
    ...(propValues.authors && { authors: propValues.authors }),
    ...(propValues.content && { content: propValues.content }),
  };
  const id = generateId(id_material, OASIS_NS);

  if (propValues.content !== undefined) {
    // escape any newlines
    if (propValues.content.includes('\n')) propValues.content = propValues.content.replace(/\n/g, '\\n');
    if (propValues.content.includes('"')) propValues.content = propValues.content.replace(/\"/g, '\\"');
    if (propValues.content.includes("'")) propValues.content = propValues.content.replace(/\'/g, "\\'");
  }

  const timestamp = new Date().toISOString();
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
  return { iri, id, query };
};
export const selectNoteQuery = (id, select) => {
  return selectNoteByIriQuery(`http://darklight.ai/ns/common#Note-${id}`, select);
};
export const selectNoteByIriQuery = (iri, select) => {
  if (!iri.startsWith('<')) iri = `<${iri}>`;
  if (select === undefined || select === null) select = Object.keys(notePredicateMap);
  const { selectionClause, predicates } = buildSelectVariables(notePredicateMap, select);
  return `
  SELECT ${selectionClause}
  FROM <tag:stardog:api:context:local>
  WHERE {
    BIND(${iri} AS ?iri)
    ?iri a <http://darklight.ai/ns/common#Note> .
    ${predicates}
  }
  `;
};
export const selectAllNotes = (select, args) => {
  if (select === undefined || select === null) select = Object.keys(notePredicateMap);
  if (!select.includes('id')) select.push('id');

  if (args !== undefined) {
    if (args.filters !== undefined) {
      for (const filter of args.filters) {
        if (!select.includes(filter.key)) select.push(filter.key);
      }
    }

    // add value of orderedBy's key to cause special predicates to be included
    if (args.orderedBy !== undefined) {
      if (!select.includes(args.orderedBy)) select.push(args.orderedBy);
    }
  }

  const { selectionClause, predicates } = buildSelectVariables(notePredicateMap, select);
  return `
  SELECT DISTINCT ?iri ${selectionClause} 
  FROM <tag:stardog:api:context:local>
  WHERE {
    ?iri a <http://darklight.ai/ns/common#Note> . 
    ${predicates}
  }
  `;
};
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
  `;
};
export const attachToNoteQuery = (id, field, itemIris) => {
  const iri = `<http://darklight.ai/ns/common#Note-${id}>`;
  if (!notePredicateMap.hasOwnProperty(field)) return null;
  const { predicate } = notePredicateMap[field];
  let statements;
  if (Array.isArray(itemIris)) {
    statements = itemIris.map((itemIri) => `${iri} ${predicate} ${itemIri}`).join('.\n        ');
  } else {
    statements = `${iri} ${predicate} ${itemIris}`;
  }
  return `
  INSERT DATA {
    GRAPH ${iri} {
      ${statements}
    }
  }
  `;
};
export const detachFromNoteQuery = (id, field, itemIris) => {
  const iri = `<http://darklight.ai/ns/common#Note-${id}>`;
  if (!notePredicateMap.hasOwnProperty(field)) return null;
  const { predicate } = notePredicateMap[field];
  let statements;
  if (Array.isArray(itemIris)) {
    statements = itemIris.map((itemIri) => `${iri} ${predicate} ${itemIri}`).join('.\n        ');
  } else {
    statements = `${iri} ${predicate} ${itemIris}`;
  }
  return `
  DELETE DATA {
    GRAPH ${iri} {
      ${statements}
    }
  }
  `;
};

// Telephone Number support functions
export const insertPhoneNumberQuery = (propValues) => {
  const id_material = {
    ...(propValues.usage_type && { usage_type: propValues.usage_type }),
    ...(propValues.phone_number && { phone_number: propValues.phone_number }),
  };
  const id = generateId(id_material, OASIS_NS);
  const iri = `<http://csrc.nist.gov/ns/oscal/common#TelephoneNumber-${id}>`;
  const insertPredicates = Object.entries(propValues)
    .filter((propPair) => phoneNumberPredicateMap.hasOwnProperty(propPair[0]))
    .map((propPair) => phoneNumberPredicateMap[propPair[0]].binding(iri, propPair[1]))
    .join('. \n      ');
  const query = `
  INSERT DATA {
    GRAPH ${iri} {
      ${iri} a <http://csrc.nist.gov/ns/oscal/common#TelephoneNumber> .
      ${iri} a <http://csrc.nist.gov/ns/oscal/common#ComplexDatatype> .
      ${iri} a <http://darklight.ai/ns/common#ComplexDatatype> .
      ${iri} <http://darklight.ai/ns/common#id> "${id}" .
      ${iri} <http://darklight.ai/ns/common#object_type> "telephone-number" . 
      ${insertPredicates}
    }
  }
  `;
  return { iri, id, query };
};
export const insertPhoneNumbersQuery = (phoneNumbers) => {
  const graphs = [];
  const phoneIris = [];
  phoneNumbers.forEach((phone) => {
    const id_material = {
      ...(phone.usage_type && { usage_type: phone.usage_type }),
      ...(phone.phone_number && { phone_number: phone.phone_number }),
    };
    const id = generateId(id_material, OASIS_NS);
    const insertPredicates = [];
    const iri = `<http://csrc.nist.gov/ns/oscal/common#TelephoneNumber-${id}>`;
    phoneIris.push(iri);
    insertPredicates.push(`${iri} a <http://csrc.nist.gov/ns/oscal/common#TelephoneNumber>`);
    insertPredicates.push(`${iri} a <http://csrc.nist.gov/ns/oscal/common#ComplexDatatype>`);
    insertPredicates.push(`${iri} a <http://darklight.ai/ns/common#ComplexDatatype>`);
    insertPredicates.push(`${iri} <http://darklight.ai/ns/common#id> "${id}"`);
    insertPredicates.push(`${iri} <http://darklight.ai/ns/common#object_type> "telephone-number"`);
    insertPredicates.push(`${iri} <http://csrc.nist.gov/ns/oscal/common#phone_number_type> "${phone.usage_type}"`);
    insertPredicates.push(`${iri} <http://csrc.nist.gov/ns/oscal/common#phone_number> "${phone.phone_number}"`);
    graphs.push(`
  GRAPH ${iri} {
    ${insertPredicates.join('.\n        ')}
  }
    `);
  });
  const query = `
  INSERT DATA {
    ${graphs.join('\n')}
  }`;
  return { phoneIris, query };
};
export const selectPhoneNumberQuery = (id, select) => {
  return selectPhoneNumberByIriQuery(`http://csrc.nist.gov/ns/oscal/common#TelephoneNumber-${id}`, select);
};
export const selectPhoneNumberByIriQuery = (iri, select) => {
  if (!iri.startsWith('<')) iri = `<${iri}>`;
  if (select === undefined || select === null) select = Object.keys(phoneNumberPredicateMap);
  const { selectionClause, predicates } = buildSelectVariables(phoneNumberPredicateMap, select);
  return `
  SELECT ${selectionClause}
  FROM <tag:stardog:api:context:local>
  WHERE {
    BIND(${iri} AS ?iri)
    ?iri a <http://csrc.nist.gov/ns/oscal/common#TelephoneNumber> .
    ${predicates}
  }
  `;
};
export const selectAllPhoneNumbers = (select, args) => {
  if (select === undefined || select === null) select = Object.keys(phoneNumberPredicateMap);
  if (!select.includes('id')) select.push('id');

  if (args !== undefined) {
    if (args.filters !== undefined) {
      for (const filter of args.filters) {
        if (!select.includes(filter.key)) select.push(filter.key);
      }
    }

    // add value of orderedBy's key to cause special predicates to be included
    if (args.orderedBy !== undefined) {
      if (!select.includes(args.orderedBy)) select.push(args.orderedBy);
    }
  }

  const { selectionClause, predicates } = buildSelectVariables(phoneNumberPredicateMap, select);
  return `
  SELECT DISTINCT ?iri ${selectionClause} 
  FROM <tag:stardog:api:context:local>
  WHERE {
    ?iri a <http://csrc.nist.gov/ns/oscal/common#TelephoneNumber> . 
    ${predicates}
  }
  `;
};
export const deletePhoneNumberQuery = (id) => {
  const iri = `http://csrc.nist.gov/ns/oscal/common#TelephoneNumber-${id}`;
  return deletePhoneNumberByIriQuery(iri);
};
export const deletePhoneNumberByIriQuery = (iri) => {
  return `
  DELETE {
    GRAPH <${iri}> {
      ?iri ?p ?o
    }
  } WHERE {
    GRAPH <${iri}> {
      ?iri a <http://csrc.nist.gov/ns/oscal/common#TelephoneNumber> .
      ?iri ?p ?o
    }
  }
  `;
};
export const attachToPhoneNumberQuery = (id, field, itemIris) => {
  const iri = `<http://csrc.nist.gov/ns/oscal/common#TelephoneNumber-${id}>`;
  if (!phoneNumberPredicateMap.hasOwnProperty(field)) return null;
  const { predicate } = phoneNumberPredicateMap[field];
  let statements;
  if (Array.isArray(itemIris)) {
    statements = itemIris.map((itemIri) => `${iri} ${predicate} ${itemIri}`).join('.\n        ');
  } else {
    statements = `${iri} ${predicate} ${itemIris}`;
  }
  return `
  INSERT DATA {
    GRAPH ${iri} {
      ${statements}
    }
  }
  `;
};
export const detachFromPhoneNumberQuery = (id, field, itemIris) => {
  const iri = `<http://csrc.nist.gov/ns/oscal/common#TelephoneNumber-${id}>`;
  if (!phoneNumberPredicateMap.hasOwnProperty(field)) return null;
  const { predicate } = phoneNumberPredicateMap[field];
  let statements;
  if (Array.isArray(itemIris)) {
    statements = itemIris.map((itemIri) => `${iri} ${predicate} ${itemIri}`).join('.\n        ');
  } else {
    statements = `${iri} ${predicate} ${itemIris}`;
  }
  return `
  DELETE DATA {
    GRAPH ${iri} {
      ${statements}
    }
  }
  `;
};
