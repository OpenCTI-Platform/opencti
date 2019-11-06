import uuid from 'uuid/v4';
import {
  append,
  assoc,
  chain,
  equals,
  filter,
  flatten,
  fromPairs,
  groupBy,
  head,
  includes,
  isEmpty,
  isNil,
  join,
  last,
  map,
  mapObjIndexed,
  mergeAll,
  mergeLeft,
  mergeRight,
  pipe,
  pluck,
  sort,
  tail,
  toPairs,
  uniq,
  uniqBy,
  uniqWith
} from 'ramda';
import moment from 'moment';
import { cursorToOffset } from 'graphql-relay/lib/connection/arrayconnection';
import Grakn from 'grakn-client';
import conf, { logger } from '../config/conf';
import { buildPagination, fillTimeSeries, randomKey } from './utils';
import { isInversed } from './graknRoles';
import {
  elDeleteInstanceIds,
  elIndex,
  elLoadByGraknId,
  elLoadById,
  elUpdate,
  INDEX_CONNECTORS,
  INDEX_EXT_REFERENCES,
  INDEX_STIX_ENTITIES,
  INDEX_STIX_OBSERVABLE,
  INDEX_STIX_RELATIONS
} from './elasticSearch';

// region global variables
const indexableTypes = [
  'Stix-Observable',
  'Stix-Domain-Entity',
  'External-Reference',
  'Stix-Observable',
  'stix_relation'
];
const dateFormat = 'YYYY-MM-DDTHH:mm:ss';
const String = 'String';
const Date = 'Date';
export const now = () =>
  moment()
    .utc()
    .toISOString();
export const graknNow = () =>
  moment()
    .utc()
    .format(dateFormat); // Format that accept grakn
export const sinceNowInMinutes = lastModified => {
  const utc = moment().utc();
  const diff = utc.diff(moment(lastModified));
  const duration = moment.duration(diff);
  return Math.floor(duration.asMinutes());
};
export const prepareDate = date =>
  moment(date)
    .utc()
    .format(dateFormat);
export const yearFormat = date => moment(date).format('YYYY');
export const monthFormat = date => moment(date).format('YYYY-MM');
export const dayFormat = date => moment(date).format('YYYY-MM-DD');
export const escape = s =>
  s && typeof s === 'string'
    ? s
        .replace(/\\/g, '\\\\')
        .replace(/;/g, '\\;')
        .replace(/,/g, '\\,')
    : s;
export const escapeString = s =>
  s ? s.replace(/\\/g, '\\\\').replace(/"/g, '\\"') : '';

// Attributes key that can contains multiple values.
export const multipleAttributes = [
  'stix_label',
  'alias',
  'grant',
  'platform',
  'required_permission'
];
export const statsDateAttributes = [
  'first_seen', // Standard
  'last_seen', // Standard
  'published', // Standard
  'expiration' // Standard
];
export const relationsToIndex = {
  'Stix-Domain-Entity': [
    {
      key: 'tags_indexed',
      query:
        'match $t isa Tag, has internal_id_key $value; (so: $x, tagging: $t) isa tagged;'
    },
    {
      key: 'createdByRef_indexed',
      query:
        'match $i isa Identity, has internal_id_key $value; (so: $x, creator: $i) isa created_by_ref;'
    },
    {
      key: 'markingDefinitions_indexed',
      query:
        'match $m isa Marking-Definition, has internal_id_key $value; (so: $x, marking: $m) isa object_marking_refs;'
    }
  ],
  'Stix-Observable': [
    {
      key: 'tags_indexed',
      query:
        'match $t isa Tag, has value $value; (so: $x, tagging: $t) isa tagged;'
    }
  ]
};
// endregion

// region client
const client = new Grakn(
  `${conf.get('grakn:hostname')}:${conf.get('grakn:port')}`
);
let session = null;
// endregion

// region basic commands
const closeTx = async gTx => {
  try {
    if (gTx.tx.isOpen()) {
      await gTx.tx.close();
    }
  } catch (err) {
    logger.error('[GRAKN] CloseReadTx error > ', err);
  }
};
const takeReadTx = async (retry = false) => {
  if (session === null) {
    session = await client.session('grakn');
  }
  try {
    const tx = await session.transaction().read();
    return { session, tx };
  } catch (err) {
    logger.error('[GRAKN] TakeReadTx error > ', err);
    await session.close();
    if (retry === false) {
      session = null;
      return takeReadTx(true);
    }
    return null;
  }
};
const executeRead = async executeFunction => {
  const rTx = await takeReadTx();
  try {
    const result = await executeFunction(rTx);
    await closeTx(rTx);
    return result;
  } catch (err) {
    await closeTx(rTx);
    logger.error('[GRAKN] executeRead error > ', err);
    throw err;
  }
};

const takeWriteTx = async (retry = false) => {
  if (session === null) {
    session = await client.session('grakn');
  }
  try {
    const tx = await session.transaction().write();
    return { session, tx };
  } catch (err) {
    logger.error('[GRAKN] TakeWriteTx error > ', err);
    if (retry === false) {
      session = null;
      return takeWriteTx(true);
    }
    return null;
  }
};
const commitWriteTx = async wTx => {
  try {
    await wTx.tx.commit();
  } catch (err) {
    logger.error('[GRAKN] CommitWriteTx error > ', err);
  }
};
export const executeWrite = async executeFunction => {
  const wTx = await takeWriteTx();
  try {
    const result = await executeFunction(wTx);
    await commitWriteTx(wTx);
    return result;
  } catch (err) {
    await closeTx(wTx);
    logger.error('[GRAKN] executeWrite error > ', err);
    throw err;
  }
};
export const write = async query => {
  const wTx = await takeWriteTx();
  try {
    await wTx.tx.query(query);
    await commitWriteTx(wTx);
  } catch (err) {
    logger.error('[GRAKN] Write error > ', err);
  } finally {
    await closeTx(wTx);
  }
};

export const graknIsAlive = async () => {
  try {
    // Just try to take a read transaction
    await executeRead(() => {});
  } catch (e) {
    logger.error(`[GRAKN] Seems down`);
    throw new Error('Grakn seems down');
  }
};
export const getGraknVersion = async () => {
  // TODO: It seems that Grakn server does not expose its version yet:
  // https://github.com/graknlabs/client-nodejs/issues/47
  return '1.5.9';
};

/**
 * Recursive fetch of every types of a concept
 * @param concept the element
 * @param currentType the current type
 * @param acc the recursive accumulator
 * @returns {Promise<Array>}
 */
export const conceptTypes = async (concept, currentType = null, acc = []) => {
  if (currentType === null) {
    const conceptType = await concept.type();
    const conceptLabel = await conceptType.label();
    acc.push(conceptLabel);
    return conceptTypes(concept, conceptType, acc);
  }
  const parentType = await currentType.sup();
  if (parentType === null) return acc;
  const conceptLabel = await parentType.label();
  acc.push(conceptLabel);
  if (conceptLabel === 'entity' || includes(conceptLabel, indexableTypes))
    return acc;
  return conceptTypes(concept, parentType, acc);
};

/**
 * Extract all vars from a grakn query
 * @param query
 */
const extractQueryVars = query => {
  return uniq(map(m => m.replace('$', ''), query.match(/\$[a-z]+/gi)));
};

/**
 * Compute the index related to concept types
 * @param types
 * @returns {String}
 */
export const inferIndexFromConceptTypes = types => {
  // Stix indexes
  if (includes('Stix-Observable', types)) return INDEX_STIX_OBSERVABLE;
  if (includes('Stix-Domain-Entity', types)) return INDEX_STIX_ENTITIES;
  if (includes('External-Reference', types)) return INDEX_EXT_REFERENCES;
  if (includes('stix_relation', types)) return INDEX_STIX_RELATIONS;
  if (includes('Connector', types)) return INDEX_CONNECTORS;
  return undefined;
};
// endregion

// region stable functions
/**
 * Query and get attribute values
 * @param type
 * @returns {{edges: *}}
 */
export const queryAttributeValues = async type => {
  return executeRead(async rTx => {
    const query = `match $x isa ${escape(type)}; get;`;
    logger.debug(`[GRAKN - infer: false] queryAttributeValues > ${query}`);
    const iterator = await rTx.tx.query(query);
    const answers = await iterator.collect();
    const result = await Promise.all(
      answers.map(async answer => {
        const attribute = answer.map().get('x');
        const attributeType = await attribute.type();
        const value = await attribute.value();
        const attributeTypeLabel = await attributeType.label();
        const replacedValue = value.replace(/\\"/g, '"').replace(/\\\\/g, '\\');
        return {
          node: {
            id: attribute.id,
            type: attributeTypeLabel,
            value: replacedValue
          }
        };
      })
    );
    return buildPagination(5000, 0, result, 5000);
  });
};

export const attributeExists = async attributeLabel => {
  return executeRead(async rTx => {
    const checkQuery = `match $x sub ${attributeLabel}; get;`;
    logger.debug(`[GRAKN - infer: false] attributeExists > ${checkQuery}`);
    await rTx.tx.query(checkQuery);
    return true;
  }).catch(() => false);
};

/**
 * Query and get attribute values
 * @param id
 * @returns {{edges: *}}
 */
export const queryAttributeValueById = async id => {
  return executeRead(async rTx => {
    const query = `match $x id ${escape(id)}; get;`;
    logger.debug(`[GRAKN - infer: false] queryAttributeValueById > ${query}`);
    const iterator = await rTx.tx.query(query);
    const answer = await iterator.next();
    const attribute = answer.map().get('x');
    const attributeType = await attribute.type();
    const value = await attribute.value();
    const attributeTypeLabel = await attributeType.label();
    const replacedValue = value.replace(/\\"/g, '"').replace(/\\\\/g, '\\');
    return {
      id: attribute.id,
      type: attributeTypeLabel,
      value: replacedValue
    };
  });
};

/**
 * Grakn generic function to delete an instance (and orphan relationships)
 * @param id
 * @returns {Promise<any[] | never>}
 */
export const deleteAttributeById = async id => {
  return executeWrite(async wTx => {
    const query = `match $x id ${escape(id)}; delete $x;`;
    logger.debug(`[GRAKN - infer: false] deleteAttributeById > ${query}`);
    await wTx.tx.query(query, { infer: false });
    return id;
  });
};

/**
 * Get relations to index
 * @param type
 * @param id
 * @returns {Promise<{}>}
 */
const getRelationsValuesToIndex = async (type, id) => {
  return executeRead(async rTx => {
    let result = {};
    if (relationsToIndex[type]) {
      result = await Promise.all(
        relationsToIndex[type].map(async relationToIndex => {
          const query = `${
            relationToIndex.query
          } $x has internal_id_key "${escapeString(id)}"; get $value;`;
          logger.debug(
            `[GRAKN - infer: false] getRelationsValuesToIndex > ${query}`
          );
          const iterator = await rTx.tx.query(query);
          const answers = await iterator.collect();
          return Promise.all(
            answers.map(async answer => {
              const attribute = answer.map().get('value');
              return attribute.value();
            })
          ).then(data => {
            return { [relationToIndex.key]: data };
          });
        })
      ).then(data => {
        return mergeAll(data);
      });
    }
    return result;
  });
};

const fixConceptRelation = elem => {
  // 01. First fix the direction of the relation
  const isInv = isInversed(elem.relationship_type, elem.fromRole);
  const invElem = !isInv
    ? elem
    : pipe(
        assoc('fromId', elem.toId),
        assoc('fromRole', elem.toRole),
        assoc('toId', elem.fromId),
        assoc('toRole', elem.fromRole)
      )(elem);
  // 02. Then change the id if relation is inferred
  if (invElem.inferred) {
    const queryPattern = `{ $rel(${invElem.fromRole}: $from, ${invElem.toRole}: $to) isa ${invElem.relationship_type}; $from id ${invElem.fromId}; $to id ${invElem.toId}; };`;
    return assoc('id', Buffer.from(queryPattern).toString('base64'), invElem);
  }
  return elem;
};

const conceptOpts = { relationsMap: new Map(), reIndex: true };
/**
 * Load any grakn instance with internal grakn ID.
 * @param concept the concept to get attributes from
 * @param relationsMap
 * @param reIndex
 * @returns {Promise}
 */
// eslint-disable-next-line prettier/prettier
const loadConcept = async (concept, { relationsMap, reIndex } = conceptOpts) => {
  const { id } = concept;
  const conceptType = concept.baseType;
  const types = await conceptTypes(concept);
  const resolveIndex = inferIndexFromConceptTypes(types);
  // 00. Try to get from cache first
  if (!reIndex && resolveIndex) {
    const cachedConcept = await elLoadByGraknId(id, [resolveIndex]);
    // Cache can be empty for listing or inferred relationship
    if (cachedConcept) return cachedConcept;
  }
  // 01. If not found continue the process.
  const parentTypeLabel = last(types);
  logger.debug(`[GRAKN - infer: false] getAttributes > ${head(types)} ${id}`);
  const attributesIterator = await concept.attributes();
  const attributes = await attributesIterator.collect();
  const attributesPromises = attributes.map(async attribute => {
    const attributeType = await attribute.type();
    const attributeLabel = await attributeType.label();
    return {
      dataType: await attributeType.dataType(),
      label: attributeLabel,
      value: await attribute.value()
    };
  });
  return Promise.all(attributesPromises)
    .then(attributesData => {
      const transform = pipe(
        map(attribute => {
          let transformedVal = attribute.value;
          const { dataType, label } = attribute;
          if (dataType === Date) {
            transformedVal = moment(attribute.value)
              .utc()
              .toISOString();
          } else if (dataType === String) {
            transformedVal = attribute.value
              .replace(/\\"/g, '"')
              .replace(/\\\\/g, '\\');
          }
          return { [label]: transformedVal };
        }), // Extract values
        chain(toPairs), // Convert to pairs for grouping
        groupBy(head), // Group by key
        map(pluck(1)), // Remove grouping boilerplate
        mapObjIndexed((num, key, obj) =>
          // eslint-disable-next-line no-nested-ternary
          Array.isArray(obj[key]) && !includes(key, multipleAttributes)
            ? head(obj[key])
            : head(obj[key]) && head(obj[key]) !== ''
            ? obj[key]
            : []
        ) // Remove extra list then contains only 1 element
      )(attributesData);
      return pipe(
        assoc('id', transform.internal_id_key),
        assoc('inferred', false),
        assoc('grakn_id', concept.id),
        assoc('parent_type', parentTypeLabel)
      )(transform);
    })
    .then(async entityData => {
      if (conceptType !== 'RELATION') return entityData;
      const isInferredPromise = concept.isInferred();
      const relationTypePromise = concept.type().then(t => t.label());
      const rolePlayers = await concept.rolePlayersMap();
      const roleEntries = Array.from(rolePlayers.entries()); // Array.from(rolePlayers.entries()).flat();
      const rolesPromises = Promise.all(
        map(async roleItem => {
          const roleId = last(roleItem)
            .values()
            .next().value.id;
          const conceptFromMap = relationsMap.get(roleId);
          return conceptFromMap
            ? head(roleItem)
                .label()
                .then(roleLabel => {
                  return {
                    [`${conceptFromMap.entity}Id`]: roleId,
                    [`${conceptFromMap.entity}Role`]: roleLabel,
                    [conceptFromMap.entity]: null // With be use lazily
                  };
                })
            : {};
        }, roleEntries)
      );
      // Wait for all promises before building the result
      const proms = [isInferredPromise, relationTypePromise, rolesPromises];
      return Promise.all(proms)
        .then(([isInferred, relationType, roles]) => {
          const relType = relationType || entityData.relationship_type;
          return pipe(
            assoc('id', isInferred ? uuid() : entityData.id),
            assoc('inferred', isInferred),
            assoc('relationship_type', relType),
            mergeRight(mergeAll(roles))
          )(entityData);
        })
        .then(rel => fixConceptRelation(rel));
    })
    .then(async data => {
      // If data is not indexed or inferred, just return it
      if (!resolveIndex || data.inferred) return data;
      const rels = await getRelationsValuesToIndex(parentTypeLabel, data.id);
      const finalData = mergeLeft(data, rels);
      return elIndex(resolveIndex, finalData);
    });
};

const findOpts = { infer: false, reIndex: true };
/**
 * Query and get entities or relations
 * @param query
 * @param entities
 * @param infer
 * @param reIndex
 * @returns {Promise}
 */
// eslint-disable-next-line prettier/prettier
export const find = async (query, entities, { infer, reIndex } = findOpts) => {
  // Remove empty values from entities
  const plainEntities = filter(e => !isEmpty(e) && !isNil(e), entities);
  return executeRead(async rTx => {
    const conceptQueryVars = extractQueryVars(query);
    logger.debug(`[GRAKN - infer: ${infer}] Find > ${query}`);
    const iterator = await rTx.tx.query(query, { infer });
    // 01. Get every concepts to fetch (unique)
    const answers = await iterator.collect();
    if (answers.length === 0) return [];
    const uniqConcepts = pipe(
      map(answer => {
        return conceptQueryVars.map(entity => {
          const concept = answer.map().get(entity);
          if (!concept) return undefined; // If specific attributes are used for filtering, ordering, ...
          return { id: concept.id, data: { concept, entity } };
        });
      }),
      flatten,
      filter(e => e !== undefined),
      uniqWith((x, y) => x.id === y.id)
    )(answers);
    const fetchingConceptsPairs = map(x => [x.id, x.data], uniqConcepts);
    const relationsMap = new Map(fetchingConceptsPairs);
    // 02. Filter concepts to create a unique list
    const fetchingConcepts = filter(
      u => includes(u.data.entity, plainEntities),
      uniqConcepts
    );
    // 03. Query concepts and rebind the data
    const queryConcepts = map(item => {
      const { concept } = item.data;
      return loadConcept(concept, { relationsMap, reIndex });
    }, fetchingConcepts);
    const resolvedConcepts = await Promise.all(queryConcepts);
    // 04. Create map from concepts
    const conceptCache = new Map(map(c => [c.grakn_id, c], resolvedConcepts));
    // 05. Bind all row to data entities
    const result = answers.map(answer => {
      const dataPerEntities = plainEntities.map(entity => {
        const concept = answer.map().get(entity);
        const conceptData = conceptCache.get(concept.id);
        return [entity, conceptData];
      });
      return fromPairs(dataPerEntities);
    });
    // 06. Filter every relation not in "openCTI path"
    // Grakn can respond with twice the relations (browse in 2 directions)
    return uniqBy(u => {
      return pipe(
        map(i => i.grakn_id),
        sort((a, b) => a.localeCompare(b))
      )(Object.values(u));
    }, result);
    // It's a special tricks for from/to relations
    // return fixReverseConceptRelations(uniqResult);
  });
};
/**
 * Query and get entities of the first row
 * @param query
 * @param entities
 * @param infer
 * @param reIndex
 * @returns {Promise<any[] | never>}
 */
// eslint-disable-next-line prettier/prettier
export const load = async (query, entities, { infer, reIndex } = findOpts) => {
  const data = await find(query, entities, { infer, reIndex });
  return head(data);
};

// Reindex functions
export const reindexByAttribute = async (type, value) => {
  const eType = escape(type);
  const eVal = escapeString(value);
  const readQuery = `match $x isa entity, has ${eType} $a; $a "${eVal}"; get;`;
  logger.debug(`[GRAKN - infer: false] attributeUpdate > ${readQuery}`);
  await find(readQuery, ['x'], { reIndex: true });
};
export const reindexByQuery = async (query, entities) => {
  const data = await find(query, entities, { reIndex: true });
  return data.length;
};

/**
 * Load any grakn instance with OpenCTI internal ID.
 * @param id element id to get
 * @returns {Promise}
 */
export const loadEntityById = async id => {
  const query = `match $x has internal_id_key "${escapeString(id)}"; get;`;
  const element = await load(query, ['x']);
  return element ? element.x : null;
};
export const loadEntityByStixId = async id => {
  const query = `match $x has stix_id_key "${escapeString(id)}"; get;`;
  const element = await load(query, ['x']);
  return element ? element.x : null;
};
export const loadEntityByGraknId = async graknId => {
  const query = `match $x id ${escapeString(graknId)}; get;`;
  const element = await load(query, ['x']);
  return element.x;
};
export const loadRelationById = async id => {
  const eid = escapeString(id);
  const query = `match $rel ($from, $to) isa relation; $rel has internal_id_key "${eid}"; get;`;
  const element = await load(query, ['rel']);
  return element ? element.rel : null;
};

/**
 * Get a single value from a Grakn query
 * @param query
 * @param infer
 * @returns {Promise<any[] | never>}
 */
export const getSingleValue = async (query, infer = false) => {
  return executeRead(async rTx => {
    logger.debug(`[GRAKN - infer: ${infer}] getSingleValue > ${query}`);
    logger.debug(`[GRAKN - infer: false] getById > ${query}`);
    const iterator = await rTx.tx.query(query, { infer });
    return iterator.next();
  });
};

/**
 * Get a single value number
 * @param query
 * @param infer
 * @returns number
 */
export const getSingleValueNumber = async (query, infer = false) => {
  return getSingleValue(query, infer).then(data => data.number());
};

/**
 * Create a relation between to element in the model without restriction.
 * @param id
 * @param input
 */
export const createRelation = async (id, input) => {
  const relationId = uuid();
  await executeWrite(async wTx => {
    const query = `match $from has internal_id_key "${escapeString(id)}";
      $to has internal_id_key "${escapeString(input.toId)}"; 
      insert $rel(${escape(input.fromRole)}: $from, ${escape(
      input.toRole
    )}: $to) 
      isa ${input.through}, has internal_id_key "${relationId}" ${
      input.stix_id_key
        ? `, has relationship_type "${escapeString(input.through)}"`
        : ''
    }
        ${
          // eslint-disable-next-line no-nested-ternary
          input.stix_id_key
            ? input.stix_id_key === 'create'
              ? `, has stix_id_key "relationship--${uuid()}"`
              : `, has stix_id_key "${escapeString(input.stix_id_key)}"`
            : ''
        } 
        ${
          input.first_seen
            ? `, has first_seen ${prepareDate(input.first_seen)}`
            : ''
        } 
        ${
          input.last_seen
            ? `, has last_seen ${prepareDate(input.last_seen)}`
            : ''
        } 
        ${input.weight ? `, has weight ${escape(input.weight)}` : ''};`;
    logger.debug(`[GRAKN - infer: false] createRelation > ${query}`);
    await wTx.tx.query(query);
  });
  const node = await elLoadById(input.toId);
  const relation = await loadRelationById(relationId);
  return { node, relation };
};

/**
 * Edit an attribute value.
 * @param id
 * @param input
 * @param wTx
 * @returns the complete instance
 */
export const updateAttribute = async (id, input, wTx) => {
  const { key, value } = input; // value can be multi valued
  // --- 00 Need update?
  const val = includes(key, multipleAttributes) ? value : head(value);
  const currentInstanceData = await elLoadById(id);
  if (equals(currentInstanceData[key], val)) {
    return id;
  }
  // --- 01 Get the current attribute types
  const escapedKey = escape(key);
  const labelTypeQuery = `match $x type ${escapedKey}; get;`;
  const labelIterator = await wTx.tx.query(labelTypeQuery);
  const labelAnswer = await labelIterator.next();
  // eslint-disable-next-line prettier/prettier
  const attrType = await labelAnswer.map().get('x').dataType();
  const typedValues = map(v => {
    if (attrType === String) return `"${escapeString(v)}"`;
    if (attrType === Date) return prepareDate(v);
    return escape(v);
  }, value);
  // --- Delete the old attribute
  const entityId = `${escapeString(id)}`;
  const deleteQuery = `match $x has internal_id_key "${entityId}", has ${escapedKey} $del via $d; delete $d;`;
  // eslint-disable-next-line prettier/prettier
  logger.debug(`[GRAKN - infer: false] updateAttribute - delete > ${deleteQuery}`);
  await wTx.tx.query(deleteQuery);
  if (typedValues.length > 0) {
    let graknValues;
    if (typedValues.length === 1) {
      graknValues = `has ${escapedKey} ${head(typedValues)}`;
    } else {
      graknValues = `${join(
        ' ',
        map(gVal => `has ${escapedKey} ${gVal},`, tail(typedValues))
      )} has ${escapedKey} ${head(typedValues)}`;
    }
    const createQuery = `match $m has internal_id_key "${escapeString(
      id
    )}"; insert $m ${graknValues};`;
    logger.debug(
      `[GRAKN - infer: false] updateAttribute - insert > ${createQuery}`
    );
    await wTx.tx.query(createQuery);
  }
  // Adding dates elements
  if (includes(key, statsDateAttributes)) {
    const dayValue = dayFormat(head(value));
    const monthValue = monthFormat(head(value));
    const yearValue = yearFormat(head(value));
    const dayInput = { key: `${key}_day`, value: [dayValue] };
    await updateAttribute(id, dayInput, wTx);
    const monthInput = { key: `${key}_month`, value: [monthValue] };
    await updateAttribute(id, monthInput, wTx);
    const yearInput = { key: `${key}_year`, value: [yearValue] };
    await updateAttribute(id, yearInput, wTx);
  }
  // Update elasticsearch
  // eslint-disable-next-line no-underscore-dangle
  let currentIndex = currentInstanceData._index;
  if (!currentIndex) {
    const conceptQuery = `match $x has internal_id_key "${entityId}"; get;`;
    const conceptIterator = await wTx.tx.query(conceptQuery);
    const conceptAnswer = await conceptIterator.next();
    const concept = await conceptAnswer.map().get('x');
    const types = await conceptTypes(concept);
    currentIndex = inferIndexFromConceptTypes(types);
  }
  if (currentIndex) {
    await elUpdate(
      currentIndex,
      currentInstanceData.grakn_id,
      assoc(key, val, {})
    );
  }
  return id;
};

export const deleteById = async id => {
  return executeWrite(async wTx => {
    const query = `match $x has internal_id_key "${escapeString(
      id
    )}"; delete $x;`;
    logger.debug(`[GRAKN - infer: false] deleteById > ${query}`);
    await elDeleteInstanceIds([id]);
    await wTx.tx.query(query, { infer: false });
    return id;
  });
};

export const deleteRelationById = async (id, relationId) => {
  return executeWrite(async wTx => {
    const query = `match $x has internal_id_key "${escapeString(
      relationId
    )}"; delete $x;`;
    logger.debug(`[GRAKN - infer: false] deleteRelationById > ${query}`);
    await wTx.tx.query(query, { infer: false });
    return loadEntityById(id).then(data => ({
      node: data,
      relation: { id: relationId }
    }));
  });
};

export const timeSeries = async (query, options) => {
  return executeRead(async rTx => {
    const {
      startDate,
      endDate,
      operation,
      field,
      interval,
      inferred = true
    } = options;
    const finalQuery = `${query}; $x has ${field}_${interval} $g; get; group $g; ${operation};`;
    logger.debug(`[GRAKN - infer: ${inferred}] timeSeries > ${finalQuery}`);
    const iterator = await rTx.tx.query(finalQuery, { infer: inferred });
    const answer = await iterator.collect();
    return Promise.all(
      answer.map(async n => {
        const date = await n.owner().value();
        const number = await n.answers()[0].number();
        return { date, value: number };
      })
    ).then(data => fillTimeSeries(startDate, endDate, interval, data));
  });
};

export const distribution = async (query, options) => {
  return executeRead(async rTx => {
    const { startDate, endDate, operation, field, inferred = false } = options;
    const finalQuery = `${query}; ${
      startDate && endDate
        ? `$rel has first_seen $fs; $fs > ${prepareDate(
            startDate
          )}; $fs < ${prepareDate(endDate)};`
        : ''
    } $x has ${field} $g; get; group $g; ${operation};`;
    logger.debug(`[GRAKN - infer: ${inferred}] distribution > ${finalQuery}`);
    const iterator = await rTx.tx.query(finalQuery, { infer: inferred });
    const answer = await iterator.collect();
    return Promise.all(
      answer.map(async n => {
        const label = await n.owner().value();
        const number = await n.answers()[0].number();
        return { label, value: number };
      })
    );
  });
};

export const deleteEntityById = async id => {
  // 00. Load everything we need to remove in elastic
  const eid = escapeString(id);
  const read = `match $x has internal_id_key "${eid}"; $y isa entity; $rel($x, $y); get;`;
  const relationsToDeIndex = await find(read, ['rel']);
  const relationsIds = map(r => r.rel.id, relationsToDeIndex);
  return executeWrite(async wTx => {
    const query = `match $x has internal_id_key "${eid}"; $z($x, $y); delete $z, $x;`;
    logger.debug(`[GRAKN - infer: false] deleteEntityById > ${query}`);
    await elDeleteInstanceIds(append(id, relationsIds));
    await wTx.tx.query(query, { infer: false });
    return id;
  });
};

/**
 * Grakn query that generate json objects for relations
 * @param query the query to process
 * @param key the instance key to get id from.
 * @param extraRelKey the key of the relation pointing the relation
 * @param infer (get inferred relationships)
 * @returns {Promise<any[] | never>}
 */
// eslint-disable-next-line prettier/prettier
export const findWithConnectedRelations = async (query, key, extraRelKey = null, infer = false) => {
  const dataFind = await find(query, [key, extraRelKey], { infer });
  return map(t => ({ node: t[key], relation: t[extraRelKey] }), dataFind);
};

/**
 * Grakn query that generate a json object for GraphQL
 * @param query the query to process
 * @param key the instance key to get id from.
 * @param relationKey the key to bind relation result.
 * @param infer
 * @returns {Promise<any[] | never>}
 */
// eslint-disable-next-line prettier/prettier
export const loadWithConnectedRelations = (query, key, relationKey = null, infer = false) => {
  return findWithConnectedRelations(query, key, relationKey, infer).then(
    result => head(result)
  );
};
// endregion

// region please refactor to use stable commands
/**
 * Load any grakn relation with base64 id containing the query pattern.
 * @param id
 * @returns {Promise}
 */
export const getRelationInferredById = async id => {
  return executeRead(async rTx => {
    const decodedQuery = Buffer.from(id, 'base64').toString('ascii');
    const query = `match ${decodedQuery} get;`;
    const queryRegex = /\$([a-z_\d]+)\s?[([a-z_]+:\s\$(\w+),\s[a-z_]+:\s\$(\w+)\)\s[a-z_]+\s([\w-]+);/i.exec(
      query
    );
    if (queryRegex === null) return {};
    const relKey = queryRegex[1];
    logger.debug(`[GRAKN - infer: true] getRelationInferredById > ${query}`);
    const answerIterator = await rTx.tx.query(query);
    const answer = await answerIterator.next();
    const rel = answer.map().get(relKey);
    const relationType = await rel.type();
    const relationTypeValue = await relationType.label();
    const rolePlayersMap = await rel.rolePlayersMap();
    const roles = rolePlayersMap.keys();
    const fromRole = roles.next().value;
    // eslint-disable-next-line prettier/prettier
    const fromObject = rolePlayersMap.get(fromRole).values().next().value;
    const fromRoleLabel = await fromRole.label();
    const toRole = roles.next().value;
    // eslint-disable-next-line prettier/prettier
    const toObject = rolePlayersMap.get(toRole).values().next().value;
    const toRoleLabel = await toRole.label();
    const relation = {
      id,
      entity_type: 'stix_relation',
      relationship_type: relationTypeValue,
      inferred: true
    };
    const fromPromise = loadConcept(fromObject);
    const toPromise = loadConcept(toObject);
    const explanation = answer.explanation();
    const explanationAnswers = explanation.answers();
    const inferences = explanationAnswers.map(explanationAnswer => {
      const explanationAnswerExplanation = explanationAnswer.explanation();
      let inferenceQuery = explanationAnswerExplanation.queryPattern();
      const inferenceQueryRegex = /(\$(\d+|rel)\s)?\([a-z_]+:\s\$(\w+),\s[a-z_]+:\s\$(\w+)\)\sisa\s([\w-]+);/i.exec(
        inferenceQuery
      );
      let relationKey;
      const [, , inferReferenceRelationKey] = inferenceQueryRegex;
      if (inferReferenceRelationKey !== undefined) {
        relationKey = inferReferenceRelationKey;
      } else {
        relationKey = randomKey(5);
        inferenceQuery = inferenceQuery.replace('(', `$${relationKey} (`);
      }
      return {
        inferenceQuery,
        relationKey,
        fromKey: inferenceQueryRegex[3],
        toKey: inferenceQueryRegex[4],
        relationType: inferenceQueryRegex[5]
      };
    });
    const inferencesQueries = pluck('inferenceQuery', inferences);
    const inferencesQuery = `match {${join(' ', inferencesQueries)} }; get;`;
    logger.debug(
      `[GRAKN - infer: true] getRelationInferredById - getInferences > ${inferencesQuery}`
    );
    const inferencesAnswerIterator = await rTx.tx.query(inferencesQuery);
    const inferencesAnswer = await inferencesAnswerIterator.next();
    const inferencesPromises = Promise.all(
      inferences.map(async inference => {
        const inferred = await inferencesAnswer
          .map()
          .get(inference.relationKey)
          .isInferred();
        const inferenceFrom = inferencesAnswer.map().get(inference.fromKey);
        const inferenceTo = inferencesAnswer.map().get(inference.toKey);
        let inferenceId;
        if (inferred) {
          const inferenceQueryRegex = /\$([a-z_\d]+)\s\([a-z_:]+\s\$([a-z_]+),\s[a-z_:]+\s\$([a-z_]+)\)/i.exec(
            inference.inferenceQuery
          );
          const entityFromKey = inferenceQueryRegex[2];
          const entityToKey = inferenceQueryRegex[3];
          const regexFromString = `\\$${entityFromKey}\\sid\\s(V\\d+);`;
          const regexFrom = new RegExp(regexFromString, 'i');
          const inferenceQueryRegexFrom = inference.inferenceQuery.match(
            regexFrom
          );
          const regexToString = `\\$${entityToKey}\\sid\\s(V\\d+);`;
          const regexTo = new RegExp(regexToString, 'i');
          const inferenceQueryRegexTo = inference.inferenceQuery.match(regexTo);

          const regexFromTypeString = `\\$${entityFromKey}\\sisa\\s[\\w-_]+;`;
          const regexFromType = new RegExp(regexFromTypeString, 'ig');
          const regexToTypeString = `\\$${entityToKey}\\sisa\\s[\\w-_]+;`;
          const regexToType = new RegExp(regexToTypeString, 'ig');

          let extractedInferenceQuery;
          if (inferenceQueryRegexFrom && inferenceQueryRegexTo) {
            extractedInferenceQuery = inference.inferenceQuery;
          } else if (inferenceQueryRegexFrom) {
            const existingId = inferenceQueryRegexFrom[1];
            extractedInferenceQuery = inference.inferenceQuery.replace(
              `$${entityFromKey} id ${existingId};`,
              `$${entityFromKey} id ${existingId}; $${entityToKey} id ${
                existingId === inferenceFrom.id
                  ? inferenceTo.id
                  : inferenceFrom.id
              };`
            );
          } else if (inferenceQueryRegexTo) {
            const existingId = inferenceQueryRegexTo[1];
            extractedInferenceQuery = inference.inferenceQuery.replace(
              `$${entityToKey} id ${existingId};`,
              `$${entityToKey} id ${existingId}; $${entityFromKey} id ${
                existingId === inferenceFrom.id
                  ? inferenceTo.id
                  : inferenceFrom.id
              };`
            );
          } else {
            extractedInferenceQuery = inference.inferenceQuery;
          }
          const finalInferenceQuery = extractedInferenceQuery
            .replace(regexFromType, '')
            .replace(regexToType, '');
          inferenceId = Buffer.from(finalInferenceQuery).toString('base64');
        } else {
          const inferenceAttributes = await loadConcept(
            inferencesAnswer.map().get(inference.relationKey)
          );
          inferenceId = inferenceAttributes.internal_id_key;
        }
        const fromAttributes = await loadConcept(inferenceFrom);
        const toAttributes = await loadConcept(inferenceTo);
        return {
          node: {
            id: inferenceId,
            inferred,
            relationship_type: inference.relationType,
            from: fromAttributes,
            to: toAttributes
          }
        };
      })
    );
    return Promise.all([fromPromise, toPromise, inferencesPromises]).then(
      ([fromResult, toResult, relationInferences]) => {
        if (isInversed(relation.relationship_type, fromRoleLabel)) {
          return pipe(
            assoc('from', toResult),
            assoc('fromRole', toRoleLabel),
            assoc('to', fromResult),
            assoc('toRole', fromRoleLabel),
            assoc('inferences', { edges: relationInferences })
          )(relation);
        }
        return pipe(
          assoc('from', fromResult),
          assoc('fromRole', fromRoleLabel),
          assoc('to', toResult),
          assoc('toRole', toRoleLabel),
          assoc('inferences', { edges: relationInferences })
        )(relation);
      }
    );
  });
};

/**
 * Grakn generic pagination query.
 * @param query
 * @param options
 * @param ordered
 * @param relationOrderingKey
 * @param infer
 * @param computeCount
 * @returns {Promise<any[] | never>}
 */
// eslint-disable-next-line prettier/prettier
export const paginate = (query, options, ordered = true, relationOrderingKey = null, infer = false, computeCount = true) => {
  try {
    const { first = 200, after, orderBy = null, orderMode = 'asc' } = options;
    const offset = after ? cursorToOffset(after) : 0;
    const instanceKey = /match\s(?:\$|{\s\$)(\w+)[\s]/i.exec(query)[1]; // We need to resolve the key instance used in query.
    const findRelationVariable = /\$(\w+)\((\w+):\$(\w+),[\s\w:$]+\)/i.exec(
      query
    );
    const relationKey = findRelationVariable && findRelationVariable[1]; // Could be setup to get relation info
    const orderingKey = relationOrderingKey
      ? `$${relationOrderingKey} has ${orderBy} $o;`
      : `$${instanceKey} has ${orderBy} $o;`;

    let count = first;
    if (computeCount === true) {
      count = getSingleValueNumber(
        `${query}; ${ordered && orderBy ? orderingKey : ''} get; count;`,
        infer
      );
    }
    const elements = findWithConnectedRelations(
      `${query}; ${ordered && orderBy ? orderingKey : ''} get; ${
        ordered && orderBy ? `sort $o ${orderMode};` : ''
      } offset ${offset}; limit ${first};`,
      instanceKey,
      relationKey,
      infer
    );
    return Promise.all([count, elements]).then(data => {
      const globalCount = data ? head(data) : 0;
      const instances = data ? last(data) : [];
      return buildPagination(first, offset, instances, globalCount);
    });
  } catch (err) {
    logger.error('[GRAKN] elPaginate error > ', err);
    return Promise.resolve(null);
  }
};

/**
 * Grakn generic pagination query
 * @param query
 * @param options
 * @param extraRel
 * @param pagination
 * @returns Promise
 */
// eslint-disable-next-line prettier/prettier
export const paginateRelationships = (query, options, extraRel = null, pagination = true) => {
  try {
    const {
      fromId,
      toId,
      fromTypes,
      toTypes,
      firstSeenStart,
      firstSeenStop,
      lastSeenStart,
      lastSeenStop,
      weights,
      inferred,
      first = 200,
      after,
      orderBy,
      orderMode = 'asc'
    } = options;
    const offset = after ? cursorToOffset(after) : 0;
    const finalQuery = `
  ${query};
  ${fromId ? `$from has internal_id_key "${escapeString(fromId)}";` : ''}
  ${toId ? `$to has internal_id_key "${escapeString(toId)}";` : ''} ${
      fromTypes && fromTypes.length > 0
        ? `${join(
            ' ',
            map(fromType => `{ $from isa ${fromType}; } or`, tail(fromTypes))
          )} { $from isa ${head(fromTypes)}; };`
        : ''
    } ${
      toTypes && toTypes.length > 0
        ? `${join(
            ' ',
            map(toType => `{ $to isa ${toType}; } or`, tail(toTypes))
          )} { $to isa ${head(toTypes)}; };`
        : ''
    } 
    ${firstSeenStart || firstSeenStop ? `$rel has first_seen $fs; ` : ''} 
    ${firstSeenStart ? `$fs > ${prepareDate(firstSeenStart)}; ` : ''} 
    ${firstSeenStop ? `$fs < ${prepareDate(firstSeenStop)}; ` : ''} 
    ${lastSeenStart || lastSeenStop ? `$rel has last_seen $ls; ` : ''} 
    ${lastSeenStart ? `$ls > ${prepareDate(lastSeenStart)}; ` : ''} 
    ${lastSeenStop ? `$ls < ${prepareDate(lastSeenStop)}; ` : ''} 
    ${
      weights
        ? `$rel has weight $weight; ${join(
            ' ',
            map(weight => `{ $weight == ${weight}; } or`, tail(weights))
          )} { $weight == ${head(weights)}; };`
        : ''
    }`;
    const orderingKey = orderBy ? `$rel has ${orderBy} $o;` : '';
    const count = getSingleValueNumber(
      `${finalQuery} ${orderingKey} get $rel, $from, $to ${
        extraRel ? `, $${extraRel}` : ''
      }${orderBy ? ', $o' : ''}; count;`,
      inferred
    );
    const elements = findWithConnectedRelations(
      `${finalQuery} ${orderingKey} get $rel, $from, $to${
        extraRel ? `, $${extraRel}` : ''
      }${orderBy ? ', $o' : ''}; ${
        orderBy ? `sort $o ${orderMode};` : ''
      } offset ${offset}; limit ${first};`,
      'rel',
      extraRel,
      inferred
    );
    if (pagination) {
      return Promise.all([count, elements]).then(data => {
        const globalCount = data ? head(data) : 0;
        const instances = data ? last(data) : [];
        return buildPagination(first, offset, instances, globalCount);
      });
    }
    return Promise.all([count, elements]).then(data => {
      const globalCount = data ? head(data) : 0;
      const instances = data ? last(data) : [];
      return { globalCount, instances };
    });
  } catch (err) {
    logger.error('[GRAKN] paginateRelationships error > ', err);
    return null;
  }
};
// endregion
