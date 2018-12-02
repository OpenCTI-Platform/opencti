import axios from 'axios';
import {
  pipe,
  toPairs,
  groupBy,
  chain,
  pluck,
  head,
  map,
  assoc,
  last,
  mapObjIndexed,
  values,
  isEmpty,
  join,
  contains
} from 'ramda';
import moment from 'moment';
import { offsetToCursor } from 'graphql-relay';
import { cursorToOffset } from 'graphql-relay/lib/connection/arrayconnection';
import conf from '../config/conf';
import { FunctionalError } from '../config/errors';
import pubsub from '../config/bus';

const gkDateFormat = 'YYYY-MM-DDTHH:mm:ss';
const gkDate = 'java.time.LocalDateTime';
const String = 'java.lang.String';
export const now = () =>
  moment()
    .utc()
    .format(gkDateFormat); // Format that accept grakn

const multipleAttributes = ['stix_label'];

const instance = axios.create({
  baseURL: conf.get('grakn:baseURL'),
  timeout: conf.get('grakn:timeout')
});

export const qk = queryDef =>
  // console.error('GRAKN START QK', queryDef);
  instance({
    method: 'post',
    url: '/kb/grakn/graql',
    data: queryDef
  }).catch(() => {
    console.error('GRAKN ERROR', queryDef);
  });

const attrByID = id => instance({ method: 'get', url: `${id}/attributes` });

const attrMap = (id, res, withType = false) => {
  const transform = pipe(
    map(attr => {
      let transformedVal = attr.value;
      const type = attr['data-type'];
      if (type === gkDate) {
        // Patch for grakn LocalDate.
        transformedVal = `${moment(attr.value).format(gkDateFormat)}Z`;
      }
      return {
        [attr.type.label]: withType
          ? { type, val: transformedVal }
          : transformedVal
      };
    }), // Extract values
    chain(toPairs), // Convert to pairs for grouping
    groupBy(head), // Group by key
    map(pluck(1)), // Remove grouping boilerplate
    mapObjIndexed((num, key, obj) =>
      obj[key].length === 1 && !contains(key, multipleAttributes)
        ? head(obj[key])
        : obj[key]
    ) // Remove extra list then contains only 1 element
  )(res.data.attributes);
  return Promise.resolve(assoc('id', id, transform));
};

export const deleteByID = id => {
  const delUser = qk(`match $x id ${id}; delete $x;`);
  return delUser.then(result => {
    if (isEmpty(result.data)) {
      throw new FunctionalError({ message: "User doesn't exist" });
    } else {
      return id;
    }
  });
};

// id must be VXXXXX
export const loadByID = (id, withType = false) =>
  qk(`match $x id ${id}; get;`).then(
    result =>
      Promise.all(
        map(line =>
          attrByID(line.x['@id']).then(res => attrMap(id, res, withType))
        )(result.data)
      ).then(r => head(r)) // Return the unique result
  );

export const loadAll = (
  type = 'User',
  first = 25,
  after = undefined,
  orderBy = 'id',
  orderMode = 'asc'
) => {
  const offset = after ? cursorToOffset(after) : 0;
  const loadCount = qk(`match $count isa ${type}; aggregate count;`).then(
    result => head(result.data)
  );
  const loadElements = qk(
    `match $x isa ${type} has ${orderBy} $o; order by $o ${orderMode}; offset ${offset}; limit ${first}; get;`
  ).then(result =>
    Promise.all(
      map(line => attrByID(line.x['@id']).then(res => attrMap(line.x.id, res)))(
        result.data
      )
    )
  );
  return Promise.all([loadCount, loadElements]).then(mergedData => {
    const globalCount = head(mergedData);
    const malwares = last(mergedData);
    const edges = pipe(
      mapObjIndexed((record, key) => {
        const node = record;
        const nodeOffset = offset + parseInt(key, 10) + 1;
        return { node, cursor: offsetToCursor(nodeOffset) };
      }),
      values
    )(malwares);
    const hasNextPage = first + offset < globalCount;
    const hasPreviousPage = offset > 0;
    const startCursor = head(edges).cursor;
    const endCursor = last(edges).cursor;
    const pageInfo = {
      startCursor,
      endCursor,
      hasNextPage,
      hasPreviousPage,
      globalCount
    };
    return { edges, pageInfo };
  });
};

export const editInput = (input, topic) => {
  const { id, key, value } = input;
  const attributeDefQuery = qk(`match $x label "${key}" sub attribute; get;`);
  return attributeDefQuery.then(attributeDefinition => {
    // Getting the data type to create next queries correctly.
    const type = head(attributeDefinition.data).x['data-type'];
    // Delete all previous attributes
    return qk(`match $m id ${id}; $m has ${key} $del; delete $del;`).then(
      () => {
        // Create new values
        const creationQuery = `match $m id ${id}; insert $m ${join(
          ' ',
          map(val => `has ${key} ${type === String ? `"${val}"` : val}`, value)
        )};`;
        return qk(creationQuery).then(() =>
          loadByID(id).then(loadedInstance => {
            pubsub.publish(topic, { data: loadedInstance });
            return loadedInstance;
          })
        );
      }
    );
  });
};

export default instance;
