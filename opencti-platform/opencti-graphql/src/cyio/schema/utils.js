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

export const optionalizePredicate = (predicate) => `OPTIONAL { ${predicate} } .`;

export const parameterizePredicate = (iri, value, predicate, binding) => (`${iri || "?iri"} ${predicate} ` + ((value === undefined || value == null) ? `?${binding}` : value )) + ' .'