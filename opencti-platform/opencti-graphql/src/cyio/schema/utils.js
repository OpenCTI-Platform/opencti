import canonicalize  from '../../utils/canonicalize.js';
import { 
  v5 as uuid5,
  v4 as uuid4, 
  parse as uuidParse } from 'uuid';

export const DARKLIGHT_NS = 'd85ba5b6-609e-58bf-a973-ca109f868e86';
export const OASIS_SCO_NS = '00abedb4-aa42-466c-9c01-fed23315a9b7';
export const OASIS_NS = 'ba6cce09-c787-5a25-a707-f52be5734460';

// Generates a deterministic ID value based on a JSON structure and a namespace
export function generateId( materials, namespace ) {
  if (materials !== undefined ) {
    if (namespace === undefined) {
      throw new TypeError('namespace must be supplied when providing materials', 'utils.js', 10 );
    }

    return uuid5( canonicalize( materials ), namespace);
  } else if ((materials === undefined || materials.length == 0) && namespace === undefined ) {
    return uuid4()
  } else {
    throw new TypeError('materials and namespace must be supplied', 'utils.js', 28 );
  }
}

// Used as part of sorting to compare values within an object
export function compareValues( key, order = 'asc') {
  return function innerSort(a, b) {
    if (!a.hasOwnProperty(key) || !b.hasOwnProperty(key)) {
      // property doesn't exist on either object
      return 0;
    }

    const varA = (typeof a[key] === 'string')
      ? a[key].toUpperCase() : a[key];
    const varB = (typeof b[key] === 'string')
      ? b[key].toUpperCase() : b[key];

    let comparison = 0;
    if (varA > varB) {
      comparison = 1;
    } else if (varA < varB) {
      comparison = -1;
    }
    return (
      (order === 'desc') ? (comparison * -1) : comparison
    );
  };
}

export const UpdateOps = {
  ADD: 'add',
  REPLACE: 'replace',
  REMOVE: 'remove'
}

export const byIdClause = (id) => `?iri <http://darklight.ai/ns/common#id> "${id}" .`;

export const optionalizePredicate = (predicate) => `OPTIONAL { ${predicate} . } `;

export const parameterizePredicate = (iri, value, predicate, binding) => (`${iri || "?iri"} ${predicate} ` + ((value === undefined || value == null) ? `?${binding}` : value ))

export const buildSelectVariables = (predicateMap, selects) => {
  const predicateMatches = selects.filter((s) => predicateMap.hasOwnProperty(s));
  const selectionClause = predicateMatches.map((s) => `?${s}`).join(" ")
  const predicates = predicateMatches.map((s) => predicateMap[s]?.optional()).join(" \n")
  return {selectionClause, predicates}
}

export const updateQuery = (iri, type, input, predicateMap) => {
  let deletePredicates = [], insertPredicates = [], replaceBindingPredicates = [];
  for(const {key, value, operation} of input) {
    if(!predicateMap.hasOwnProperty(key)) continue;
    for(const itr of value) {
      const predicate = predicateMap[key].binding(iri, itr);
      switch (operation) {
        case UpdateOps.ADD:
          insertPredicates.push(predicate);
          break;
        case UpdateOps.REPLACE:
          insertPredicates.push(predicate);
          replaceBindingPredicates.push(predicateMap[key].binding(iri))
          break;
        case UpdateOps.REMOVE:
          deletePredicates.push(predicate);
          break;
      }
    }
  }
  return `
DELETE {
  GRAPH ?g {
    ${deletePredicates.join('\n      ')}
    ${replaceBindingPredicates.join('\n      ')}
  }
} INSERT {
  GRAPH ?g {
    ${insertPredicates.join('\n      ')}
  }
} WHERE {
  GRAPH ?g {
    <${iri}> a <${type}> .
    ${replaceBindingPredicates.join('\n      ')}
  }
}
  `;
}
