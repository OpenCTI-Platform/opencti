import { CyioError, optionalizePredicate, parameterizePredicate, buildSelectVariables } from '../../utils.js';
import { objectMap } from '../global-utils.js';

// Reducer Selection
export function getReducer(type) {
  switch (type) {
    case 'ENTITY':
      return entitiesReducer;
    default:
      throw new Error(`Unsupported reducer type ' ${type}'`);
  }
}

//
// Reducers
//
const entitiesReducer = (item) => {
  // if no object type was returned, compute the type from the IRI
  if (item.object_type === undefined) {
    if (item.iri.includes('Software')) item.object_type = 'software';
    if (item.iri.includes('Hardware')) item.object_type = 'hardware';
  }

  return {
    iri: item.iri,
    id: item.id,
    ...(item.object_type && { entity_type: item.object_type }),
    ...(item.created && { created: item.created }),
    ...(item.modified && { modified: item.modified }),
  };
};

export const entitiesCountQuery = (args) => {
  let classIri;
  let predicate;
  let filterClause;
  let type;
  let field;
  let endDate;
  const matchPredicates = [];
  if ('type' in args) {
    type = args.type.toLowerCase();
    field = 'object_type';
  } else if (args.field === 'entity_type') {
    field = 'object_type';
    for (let match of args.match) {
      match = match.toLowerCase();
      type = match;
      if (!objectMap.hasOwnProperty(match)) {
        let found = false;
        for (const [key, value] of Object.entries(objectMap)) {
          // check for alternate key
          if (value.alternateKey != undefined && match == value.alternateKey) {
            type = key;
            found = true;
            break;
          }
          // check if the GraphQL type name was supplied
          if (match == value.graphQLType) {
            type = key;
            found = true;
            break;
          }
        }
        if (!found) throw new CyioError(`Unknown field '${args.match}'`);
      }
    }
  }
  if (type === undefined) throw new CyioError(`Unable to determine object type`);

  // Validate field is defined
  const { predicateMap } = objectMap[type];
  if ('field' in args && args.field !== 'entity_type') {
    field = args.field;
    if (!predicateMap.hasOwnProperty(field)) throw new CyioError(`Field '${field}' is not defined for the entity.`);
    predicate = predicateMap[args.field].predicate;
  }

  while (objectMap[type].parent !== undefined) {
    type = objectMap[type].parent;
  }

  // construct the IRI
  classIri = `<${objectMap[type].classIri}>`;

  if ('endDate' in args && args.endDate instanceof Date) {
    // convert end date to string, if specified
    endDate = args.endDate.toISOString();
  } else {
    // uses the current date and time
    endDate = new Date().toISOString();
  }
  filterClause = `
    ?iri <http://darklight.ai/ns/common#created> ?created .
    FILTER (?created > "${endDate}"^^xsd:dateTime)
    `;

  if (args.field !== 'entity_type') {
    if ('match' in args && args.match.length > 0) {
      let dataType = '';
      let values = '';

      // extract the datatype as its needed for the match strings
      const binding = predicateMap[args.field].binding('?iri', args.field);
      if (binding.includes('^^')) {
        dataType = binding.substr(binding.indexOf('^^'));
      }

      for (const match of args.match) {
        values += ` "${match}"${dataType}`;
      }
      if (values.length > 0) {
        values = values.trim();
        matchPredicates.push(`  VALUES ?o {${values}} .`);
        matchPredicates.push(`  ?iri ${predicate} ?o .`);
      }
    }
  }

  return `
  PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>
  SELECT (COUNT(DISTINCT ?iri) AS ?total) ?count
  FROM <tag:stardog:api:context:local>
  WHERE {
    ?iri a ${classIri} .
    ${matchPredicates.join('\n')}
    OPTIONAL {
      {
        SELECT (COUNT(DISTINCT ?iri) AS ?count)
        WHERE {
          ?iri a ${classIri} .
          ${matchPredicates.join('\n')}
          ${filterClause}
        }
      }
    }
  } GROUP BY ?count
  `;
};

export const entitiesTimeSeriesQuery = (args) => {
  let classIri;
  let predicate;
  let type;
  let field;
  let startDate;
  let endDate;
  const matchPredicates = [];
  if ('type' in args) {
    type = args.type.toLowerCase();
    field = 'object_type';
  } else if (args.field === 'entity_type') {
    field = 'object_type';
    for (let match of args.match) {
      match = match.toLowerCase();
      type = match;
      if (!objectMap.hasOwnProperty(match)) {
        let found = false;
        for (const [key, value] of Object.entries(objectMap)) {
          // check for alternate key
          if (value.alternateKey != undefined && match == value.alternateKey) {
            type = key;
            found = true;
            break;
          }
          // check if the GraphQL type name was supplied
          if (match == value.graphQLType) {
            type = key;
            found = true;
            break;
          }
        }
        if (!found) throw new CyioError(`Unknown field '${args.match}'`);
      }
    }
  }
  if (type === undefined) throw new CyioError(`Unable to determine object type`);

  // Validate field is defined
  const { predicateMap } = objectMap[type];
  if ('field' in args && args.field !== 'entity_type') {
    field = args.field;
    if (!predicateMap.hasOwnProperty(field)) throw new CyioError(`Field '${field}' is not defined for the entity.`);
    predicate = predicateMap[args.field].predicate;
  }

  while (objectMap[type].parent !== undefined) {
    type = objectMap[type].parent;
  }

  // construct the IRI
  if ('objectId' in args) {
    classIri = `<${objectMap[type].iriTemplate}-${args.objectId}>`;
  } else {
    classIri = `<${objectMap[type].classIri}>`;
  }

  if ('startDate' in args && args.startDate instanceof Date) {
    // convert start date to string, if specified
    startDate = args.startDate.toISOString();
  } else {
    // use Epoch time
    startDate = '1970-01-01T00:00:00Z';
  }
  if ('endDate' in args && args.endDate instanceof Date) {
    // convert end date to string, if specified
    endDate = args.endDate.toISOString();
  } else {
    // uses the current date and time
    endDate = new Date().toISOString();
  }

  if (args.field !== 'entity_type') {
    if ('match' in args && args.match.length > 0) {
      let values = '';
      for (const match of args.match) {
        values += ` "${match}"`;
      }
      if (values.length > 0) {
        values = values.trim();
        matchPredicates.push(`  Values ?o {${values}} .`);
        matchPredicates.push(`  ?iri ${predicate} ?o .`);
      }
    }
  }

  return `
  PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>
  SELECT ?iri ?created
  FROM <tag:stardog:api:context:local>
  WHERE {
    ?iri a ${classIri} .
    ${matchPredicates.join('\n')}
    ?iri <http://darklight.ai/ns/common#created> ?created .
    FILTER (?created > "${startDate}"^^xsd:dateTime && ?created < "${endDate}"^^xsd:dateTime)
  } GROUP BY ?iri ?created
  `;
};

export const entitiesDistributionQuery = (args) => {
  let select;
  let classIri;
  let predicate;
  let type;
  let field;
  let startDate;
  let endDate;
  let occurrenceClause = '';
  let occurrenceQuery = '';
  let occurrenceGroupBy = '';
  const matchPredicates = [];
  const insertSelections = [];
  if ('type' in args) {
    type = args.type.toLowerCase();
    field = 'object_type';
  } else if (args.field === 'entity_type') {
    field = 'object_type';
    for (let match of args.match) {
      match = match.toLowerCase();
      type = match;
      if (!objectMap.hasOwnProperty(match)) {
        let found = false;
        for (const [key, value] of Object.entries(objectMap)) {
          // check for alternate key
          if (value.alternateKey != undefined && match == value.alternateKey) {
            type = key;
            found = true;
            break;
          }
          // check if the GraphQL type name was supplied
          if (match == value.graphQLType) {
            type = key;
            found = true;
            break;
          }
        }
        if (!found) throw new CyioError(`Unknown field '${args.match}'`);
      }
    }
  }
  if (type === undefined) throw new CyioError(`Unable to determine object type`);

  // Validate field is defined
  const { predicateMap } = objectMap[type];
  if ('field' in args && args.field !== 'entity_type') {
    field = args.field;
    if (args.field !== 'occurrences' && args.field !== 'risk_level') {
      if (!predicateMap.hasOwnProperty(field)) throw new CyioError(`Field '${field}' is not defined for the entity.`);
      predicate = predicateMap[args.field].predicate;
    }
  }

  while (objectMap[type].parent !== undefined) {
    type = objectMap[type].parent;
  }

  // construct the IRI
  if ('objectId' in args) {
    classIri = `<${objectMap[type].iriTemplate}-${args.objectId}>`;
  } else {
    classIri = `<${objectMap[type].classIri}>`;
  }

  // build filter for start and end dates
  if ('startDate' in args && args.startDate instanceof Date) {
    // convert start date to string, if specified
    startDate = args.startDate.toISOString();
  } else {
    // use Epoch time
    startDate = '1970-01-01T00:00:00Z';
  }
  if ('endDate' in args && args.endDate instanceof Date) {
    // convert end date to string, if specified
    endDate = args.endDate.toISOString();
  } else {
    // uses the current date and time
    endDate = new Date().toISOString();
  }

  if (args.field !== 'risk_level' && args.field !== 'occurrences') {
    // Build values clause to match only those items specified
    if ('match' in args && args.field !== 'entity_type') {
      if ('match' in args && args.match.length > 0) {
        let values = '';
        for (const match of args.match) {
          values += ` "${match}"`;
        }
        if (values.length > 0) {
          values = values.trim();
          matchPredicates.push(`  Values ?o {${values}} .`);
          matchPredicates.push(`  ?iri ${predicate} ?o .`);
        }
      }
    }
  }

  let selectionVariables = '';
  let predicateStatements = '';
  if (select === undefined || select === null) select = [];
  if (!select.includes('id')) select.push('id');
  if (!select.includes('entity_type')) select.push('entity_type');
  // if retrieving for risk_level or occurrences
  if (args.field === 'risk_level' || args.field === 'occurrences') {
    if (!select.includes('name')) select.push('name');
    insertSelections.push(`(MIN(?collected) AS ?first_seen) (MAX(?collected) as ?last_seen)`);

    // retrieve fields necessary for risk level
    if (!select.includes('cvss2_base_score')) select.push('cvss2_base_score');
    if (!select.includes('cvss2_temporal_score')) select.push('cvss2_temporal_score');
    if (!select.includes('cvss3_base_score')) select.push('cvss3_base_score');
    if (!select.includes('cvss3_temporal_score')) select.push('cvss3_temporal_score');
    insertSelections.push(
      `(MAX(?cvss2_base_score) AS ?cvssV2Base_score) (MAX(?cvss2_temporal_score) as ?cvssV2Temporal_score)`
    );
    insertSelections.push(
      `(MAX(?cvss3_base_score) AS ?cvssV3Base_score) (MAX(?cvss3_temporal_score) as ?cvssV3Temporal_score)`
    );

    // retrieve fields necessary for occurrences
    occurrenceClause = '?occurrences';
    occurrenceQuery = `
      OPTIONAL {
        {
          SELECT DISTINCT ?iri (COUNT(DISTINCT ?subjects) AS ?count)
          WHERE {
            ?iri <http://csrc.nist.gov/ns/oscal/assessment/common#related_observations> ?related_observations .
            ?related_observations <http://csrc.nist.gov/ns/oscal/assessment/common#subjects> ?subjects .
            ?subjects <http://darklight.ai/ns/oscal/assessment/common#subject_context> "target" .
      }
          GROUP BY ?iri
        }
      }
      BIND(IF(!BOUND(?count), 0, ?count) AS ?occurrences)
    `;
    occurrenceGroupBy = `?occurrences ORDER BY DESC(?occurrences)`;

    // build selectionClause and predicate list
    let { selectionClause, predicates } = buildSelectVariables(predicateMap, select);

    // remove any select items pushed from selectionClause to reduce what is not returned
    selectionClause = selectionClause.replace('?cvss2_base_score', '');
    selectionClause = selectionClause.replace('?cvss2_temporal_score', '');
    selectionClause = selectionClause.replace('?cvss3_base_score', '');
    selectionClause = selectionClause.replace('?cvss3_temporal_score', '');

    selectionVariables = selectionClause.trim();
    predicateStatements = predicates.trim();
  }

  return `
  PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>
  SELECT ?iri ?created ?o ${selectionVariables.trim()} ${occurrenceClause}
  ${insertSelections.join('\n')}
  FROM <tag:stardog:api:context:local>
  WHERE {
    ?iri a ${classIri} .
    ${predicateStatements}
    OPTIONAL { ?iri <http://csrc.nist.gov/ns/oscal/assessment/common#related_observations>/<http://csrc.nist.gov/ns/oscal/assessment/common#collected> ?collected . }
    ${matchPredicates.join('\n')}
    ${occurrenceQuery}
    ?iri <http://darklight.ai/ns/common#created> ?created .
    FILTER (?created > "${startDate}"^^xsd:dateTime && ?created < "${endDate}"^^xsd:dateTime)
  } GROUP BY ?iri ?created ?o ${selectionVariables.trim()} ${occurrenceGroupBy}
  `;
};

// Predicate Map
export const entityPredicateMap = {
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
};

// Singularization Schema
export const dashboardSingularizeSchema = {
  singularizeVariables: {
    '': false, // so there is an object as the root instead of an array
    id: true,
    iri: true,
    object_type: true,
    entity_type: true,
    o: true,
    total: true,
    count: true,
    created: true,
    modified: true,
    name: true,
    risk_status: true,
    deadline: true,
    accepted: true,
    false_positive: true,
    priority: true,
    vendor_dependency: true,
    remediation_type: true,
    remediation_lifecycle: true,
    occurrences: true,
    first_seen: true,
    last_seen: true,
    cvss2_base_score: true,
    cvss2_temporal_score: true,
    cvss3_base_score: true,
    cvss3_temporal_score: true,
    cvssV2Base_score: true,
    cvssV2Temporal_score: true,
    cvssV3Base_score: true,
    cvssV3Temporal_score: true,
  },
};
