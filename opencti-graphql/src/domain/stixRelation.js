import {
  head,
  join,
  map,
  append,
  omit,
  concat,
  sum,
  pluck,
  forEach,
  assoc,
  evolve,
  tail,
  curry,
  values,
  prop,
  groupBy,
  reduce,
  add,
  take,
  sortWith,
  descend,
  ascend,
  pipe,
  dropRepeats
} from 'ramda';
import { cursorToOffset } from 'graphql-relay/lib/connection/arrayconnection';
import uuid from 'uuid/v4';
import { delEditContext, setEditContext } from '../database/redis';
import {
  deleteById,
  updateAttribute,
  getById,
  getRelationById,
  getRelationInferredById,
  notify,
  now,
  paginate,
  paginateRelationships,
  prepareDate,
  dayFormat,
  monthFormat,
  yearFormat,
  prepareString,
  timeSeries,
  distribution,
  takeWriteTx,
  getObjectsWithoutAttributes,
  buildPagination
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';

const sumBy = attribute => vals =>
  reduce(
    (current, val) => evolve({ [attribute]: add(val[attribute]) }, current),
    head(vals),
    tail(vals)
  );

const groupSumBy = curry((groupOn, sumOn, vals) =>
  values(map(sumBy(sumOn))(groupBy(prop(groupOn), vals)))
);

export const findAll = args =>
  paginateRelationships(
    `match $rel($from, $to) isa ${
      args.relationType ? args.relationType : 'stix_relation'
    }`,
    args
  );

export const findByStixId = args =>
  paginateRelationships(
    `match $rel($from, $to); $rel has stix_id "${prepareString(args.stix_id)}"`,
    args
  );

export const search = args =>
  paginateRelationships(
    `match $rel($from, $to); $rel has name $name; $rel has description $desc; { $name contains "${prepareString(
      args.search
    )}"; } or { $desc contains "${prepareString(args.search)}"; }`,
    args
  );

export const findAllWithInferences = async args => {
  const entities = await getObjectsWithoutAttributes(
    `match $x; (${args.resolveRelationRole}: $from, $x) isa ${
      args.resolveRelationType
    }; ${
      args.resolveRelationToTypes
        ? `${join(
            ' ',
            map(
              resolveRelationToType =>
                `{ $x isa ${resolveRelationToType}; } or`,
              args.resolveRelationToTypes
            )
          )} { $x isa ${head(args.resolveRelationToTypes)}; };`
        : ''
    } $from id ${args.fromId}; get $x;`,
    'x',
    null,
    true
  );
  const fromIds = append(args.fromId, map(e => e.node.id, entities));
  const query = `match $rel($from, $to) isa ${
    args.relationType ? args.relationType : 'stix_relation'
  }; ${join(
    ' ',
    map(fromId => `{ $from id ${fromId}; } or`, fromIds)
  )} { $from id ${head(fromIds)}; }`;
  const resultPromise = await paginateRelationships(
    query,
    assoc('inferred', false, omit(['fromId'], args)),
    null,
    !args.resolveViaTypes
  );
  if (args.resolveViaTypes) {
    const viaPromise = Promise.all(
      map(async resolveViaType => {
        const viaQuery = `match $from; $rel($from, $entity) isa ${
          args.relationType ? args.relationType : 'stix_relation'
        }; ${join(
          ' ',
          map(fromId => `{ $from id ${fromId}; } or`, fromIds)
        )} { $from id ${head(fromIds)}; }; $entity isa ${
          resolveViaType.entityType
        }; $link(${resolveViaType.relationRole}: $entity, $to) isa ${
          resolveViaType.relationType
        }`;
        return paginateRelationships(
          viaQuery,
          omit(['fromId'], args),
          null,
          false
        );
      })(args.resolveViaTypes)
    );
    const viaRelationQueries = map(
      resolveViaType =>
        `match $from; $rel($from, $entity) isa ${
          args.relationType ? args.relationType : 'stix_relation'
        }; ${join(
          ' ',
          map(fromId => `{ $from id ${fromId}; } or`, fromIds)
        )} { $from id ${head(fromIds)}; }; $link(${
          resolveViaType.relationRole
        }: $rel, $to) isa ${resolveViaType.relationType}`
    )(args.resolveViaTypes);
    const viaOfRelationPromise = Promise.all(
      map(async viaRelationQuery =>
        paginateRelationships(
          viaRelationQuery,
          omit(['fromId'], args),
          null,
          false
        )
      )(dropRepeats(viaRelationQueries))
    );
    return Promise.all([resultPromise, viaPromise, viaOfRelationPromise]).then(
      ([result, via, viaRelation]) => {
        const { first = 200, after } = args;
        const offset = after ? cursorToOffset(after) : 0;
        const globalCount =
          result.globalCount +
          sum(pluck('globalCount', via)) +
          sum(pluck('globalCount', viaRelation));
        let viaInstances = [];
        forEach(n => {
          viaInstances = concat(viaInstances, n.instances);
        }, via);
        let viaRelationInstances = [];
        forEach(n => {
          viaRelationInstances = concat(viaRelationInstances, n.instances);
        }, viaRelation);
        const instances = concat(viaInstances, viaRelationInstances);
        const finalInstances = concat(result.instances, instances);
        return buildPagination(first, offset, finalInstances, globalCount);
      }
    );
  }
  return resultPromise;
};

export const stixRelationsTimeSeries = args =>
  timeSeries(
    `match $x($from, $to) isa ${
      args.relationType ? args.relationType : 'stix_relation'
    }; ${
      args.toTypes
        ? `${join(
            ' ',
            map(toType => `{ $to isa ${toType}; } or`, args.toTypes)
          )} { $to isa ${head(args.toTypes)}; };`
        : ''
    } ${
      args.fromId ? `$from id ${args.fromId}` : '$from isa Stix-Domain-Entity'
    }`,
    args
  );

export const stixRelationsTimeSeriesWithInferences = async args => {
  const entities = await getObjectsWithoutAttributes(
    `match $x; (${args.resolveRelationRole}: $from, $x) isa ${
      args.resolveRelationType
    }; ${
      args.resolveRelationToTypes
        ? `${join(
            ' ',
            map(
              resolveRelationToType =>
                `{ $x isa ${resolveRelationToType}; } or`,
              args.resolveRelationToTypes
            )
          )} { $x isa ${head(args.resolveRelationToTypes)}; };`
        : ''
    } $from id ${args.fromId}; get $x;`,
    'x',
    null,
    true
  );
  const fromIds = append(args.fromId, map(e => e.node.id, entities));
  const query = `match $x($from, $to) isa ${
    args.relationType ? args.relationType : 'stix_relation'
  }; ${join(
    ' ',
    map(fromId => `{ $from id ${fromId}; } or`, fromIds)
  )} { $from id ${head(fromIds)}; }${
    args.toTypes
      ? `; ${join(
          ' ',
          map(toType => `{ $to isa ${toType}; } or`, args.toTypes)
        )} { $to isa ${head(args.toTypes)}; }`
      : ''
  }`;
  const resultPromise = timeSeries(query, assoc('inferred', false, args));
  if (args.resolveViaTypes) {
    const viaPromise = Promise.all(
      map(resolveViaType => {
        const viaQuery = `match $from; $x($from, $entity) isa ${
          args.relationType ? args.relationType : 'stix_relation'
        }; ${join(
          ' ',
          map(fromId => `{ $from id ${fromId}; } or`, fromIds)
        )} { $from id ${head(fromIds)}; }; $entity isa ${
          resolveViaType.entityType
        }; $link(${resolveViaType.relationRole}: $entity, $to) isa ${
          resolveViaType.relationType
        } ${
          args.toTypes
            ? `; ${join(
                ' ',
                map(toType => `{ $to isa ${toType}; } or`, args.toTypes)
              )} { $to isa ${head(args.toTypes)}; }`
            : ''
        }`;
        return timeSeries(viaQuery, assoc('inferred', true, args));
      })(args.resolveViaTypes)
    );
    const viaRelationQueries = map(
      resolveViaType =>
        `match $from; $x($from, $entity) isa ${
          args.relationType ? args.relationType : 'stix_relation'
        }; ${join(
          ' ',
          map(fromId => `{ $from id ${fromId}; } or`, fromIds)
        )} { $from id ${head(fromIds)}; }; $link(${
          resolveViaType.relationRole
        }: $x, $to) isa ${resolveViaType.relationType} ${
          args.toTypes
            ? `; ${join(
                ' ',
                map(toType => `{ $to isa ${toType}; } or`, args.toTypes)
              )} { $to isa ${head(args.toTypes)}; }`
            : ''
        }`
    )(args.resolveViaTypes);
    const viaOfRelationPromise = Promise.all(
      map(viaRelationQuery => {
        return timeSeries(viaRelationQuery, assoc('inferred', true, args));
      })(dropRepeats(viaRelationQueries))
    );
    return Promise.all([resultPromise, viaPromise, viaOfRelationPromise]).then(
      ([result, via, viaRelation]) => {
        let viaResult = [];
        forEach(n => {
          viaResult = concat(viaResult, n);
        }, via);
        let viaRelationResult = [];
        forEach(n => {
          viaRelationResult = concat(viaRelationResult, n);
        }, viaRelation);
        const data = concat(viaResult, viaRelationResult);
        const finalData = concat(result, data);
        return groupSumBy('date', 'value', finalData);
      }
    );
  }
  return resultPromise;
};

export const stixRelationsDistribution = args => {
  const { limit = 10 } = args;
  return distribution(
    `match $rel($from, $x) isa ${
      args.relationType ? args.relationType : 'stix_relation'
    }; ${
      args.toTypes
        ? `${join(
            ' ',
            map(toType => `{ $x isa ${toType}; } or`, args.toTypes)
          )} { $x isa ${head(args.toTypes)}; };`
        : ''
    } ${
      args.fromId ? `$from id ${args.fromId}` : '$from isa Stix-Domain-Entity'
    }`,
    args
  ).then(result => {
    if (args.order === 'asc') {
      return take(limit, sortWith([ascend(prop('value'))])(result));
    }
    return take(limit, sortWith([descend(prop('value'))])(result));
  });
};
export const stixRelationsDistributionWithInferences = async args => {
  const { limit = 10 } = args;
  const entities = await getObjectsWithoutAttributes(
    `match $x; (${args.resolveRelationRole}: $from, $x) isa ${
      args.resolveRelationType
    }; ${
      args.resolveRelationToTypes
        ? `${join(
            ' ',
            map(
              resolveRelationToType =>
                `{ $x isa ${resolveRelationToType}; } or`,
              args.resolveRelationToTypes
            )
          )} { $x isa ${head(args.resolveRelationToTypes)}; };`
        : ''
    } $from id ${args.fromId}; get $x;`,
    'x',
    null,
    true
  );
  const fromIds = append(args.fromId, map(e => e.node.id, entities));
  const query = `match $rel($from, $x) isa ${
    args.relationType ? args.relationType : 'stix_relation'
  }; ${join(
    ' ',
    map(fromId => `{ $from id ${fromId}; } or`, fromIds)
  )} { $from id ${head(fromIds)}; }${
    args.toTypes
      ? `; ${join(
          ' ',
          map(toType => `{ $x isa ${toType}; } or`, args.toTypes)
        )} { $x isa ${head(args.toTypes)}; }`
      : ''
  }`;
  const resultPromise = distribution(query, assoc('inferred', false, args));
  if (args.resolveViaTypes) {
    const viaPromise = Promise.all(
      map(resolveViaType => {
        const viaQuery = `match $from; $rel($from, $entity) isa ${
          args.relationType ? args.relationType : 'stix_relation'
        }; ${join(
          ' ',
          map(fromId => `{ $from id ${fromId}; } or`, fromIds)
        )} { $from id ${head(fromIds)}; }; $entity isa ${
          resolveViaType.entityType
        }; $link(${resolveViaType.relationRole}: $entity, $x) isa ${
          resolveViaType.relationType
        }; ${
          args.toTypes
            ? `${join(
                ' ',
                map(toType => `{ $x isa ${toType}; } or`, args.toTypes)
              )} { $x isa ${head(args.toTypes)}; };`
            : ''
        } $rel has first_seen $o`;
        return distribution(viaQuery, assoc('inferred', true, args));
      })(args.resolveViaTypes)
    );
    const viaRelationQueries = map(
      resolveViaType =>
        `match $from; $rel($from, $entity) isa ${
          args.relationType ? args.relationType : 'stix_relation'
        }; ${join(
          ' ',
          map(fromId => `{ $from id ${fromId}; } or`, fromIds)
        )} { $from id ${head(fromIds)}; }; $link(${
          resolveViaType.relationRole
        }: $rel, $x) isa ${resolveViaType.relationType}; ${
          args.toTypes
            ? `${join(
                ' ',
                map(toType => `{ $x isa ${toType}; } or`, args.toTypes)
              )} { $x isa ${head(args.toTypes)}; };`
            : ''
        } $rel has first_seen $o`
    )(args.resolveViaTypes);
    const viaOfRelationPromise = Promise.all(
      map(viaRelationQuery =>
        distribution(viaRelationQuery, assoc('inferred', true, args))
      )(dropRepeats(viaRelationQueries))
    );
    return Promise.all([resultPromise, viaPromise, viaOfRelationPromise]).then(
      ([result, via, viaRelation]) => {
        let viaResult = [];
        forEach(n => {
          viaResult = concat(viaResult, n);
        }, via);
        let viaRelationResult = [];
        forEach(n => {
          viaRelationResult = concat(viaRelationResult, n);
        }, viaRelation);
        const data = concat(viaResult, viaRelationResult);
        const finalData = concat(result, data);
        if (args.order === 'asc') {
          return take(
            limit,
            sortWith([ascend(prop('value'))])(
              groupSumBy('label', 'value', finalData)
            )
          );
        }
        return take(
          limit,
          sortWith([descend(prop('value'))])(
            groupSumBy('label', 'value', finalData)
          )
        );
      }
    );
  }
  if (args.order === 'asc') {
    return resultPromise.then(data =>
      take(limit, sortWith([ascend(prop('value'))])(data))
    );
  }
  return resultPromise.then(data =>
    take(limit, sortWith([descend(prop('value'))])(data))
  );
};

export const findById = stixRelationId => getRelationById(stixRelationId);
export const findByIdInferred = stixRelationId =>
  getRelationInferredById(stixRelationId);

export const markingDefinitions = (stixRelationId, args) =>
  paginate(
    `match $marking isa Marking-Definition; 
    $rel(marking:$marking, so:$stixRelation) isa object_marking_refs; 
    $stixRelation id ${stixRelationId}`,
    args
  );

export const reports = (stixRelationId, args) =>
  paginate(
    `match $report isa Report; 
    $rel(knowledge_aggregation:$report, so:$stixRelation) isa object_refs; 
    $stixRelation id ${stixRelationId}`,
    args
  );

export const locations = (stixRelationId, args) =>
  paginate(
    `match $location isa Country; 
    $rel(location:$location, localized:$stixRelation) isa localization; 
    $stixRelation id ${stixRelationId}`,
    args,
    false
  );

export const addStixRelation = async (user, stixRelation) => {
  const wTx = await takeWriteTx();
  const stixRelationIterator = await wTx.query(`match $from id ${
    stixRelation.fromId
  }; 
    $to id ${stixRelation.toId}; 
    insert $stixRelation(${stixRelation.fromRole}: $from, ${
    stixRelation.toRole
  }: $to) 
    isa ${stixRelation.relationship_type} 
    has relationship_type "${prepareString(
      stixRelation.relationship_type.toLowerCase()
    )}";
    $stixRelation has type "stix-relation";
    $stixRelation has stix_id "${
      stixRelation.stix_id
        ? prepareString(stixRelation.stix_id)
        : `relationship--${uuid()}`
    }";
    $stixRelation has name "";
    $stixRelation has description "${prepareString(stixRelation.description)}";
    $stixRelation has weight ${stixRelation.weight};
    $stixRelation has first_seen ${prepareDate(stixRelation.first_seen)};
    $stixRelation has first_seen_day "${dayFormat(stixRelation.first_seen)}";
    $stixRelation has first_seen_month "${monthFormat(
      stixRelation.first_seen
    )}";
    $stixRelation has first_seen_year "${yearFormat(stixRelation.first_seen)}";
    $stixRelation has last_seen ${prepareDate(stixRelation.last_seen)};
    $stixRelation has last_seen_day "${dayFormat(stixRelation.last_seen)}";
    $stixRelation has last_seen_month "${monthFormat(stixRelation.last_seen)}";
    $stixRelation has last_seen_year "${yearFormat(stixRelation.last_seen)}";
    $stixRelation has created ${
      stixRelation.created ? prepareDate(stixRelation.created) : now()
    };
    $stixRelation has modified ${
      stixRelation.modified ? prepareDate(stixRelation.modified) : now()
    };
    $stixRelation has revoked false;
    $stixRelation has created_at ${now()};
    $stixRelation has created_at_day "${dayFormat(now())}";
    $stixRelation has created_at_month "${monthFormat(now())}";
    $stixRelation has created_at_year "${yearFormat(now())}";        
    $stixRelation has updated_at ${now()};
  `);
  const createStixRelation = await stixRelationIterator.next();
  const createdStixRelationId = await createStixRelation
    .map()
    .get('stixRelation').id;

  if (stixRelation.markingDefinitions) {
    const createMarkingDefinition = markingDefinition =>
      wTx.query(
        `match $from id ${createdStixRelationId}; $to id ${markingDefinition}; insert (so: $from, marking: $to) isa object_marking_refs;`
      );
    const markingDefinitionsPromises = map(
      createMarkingDefinition,
      stixRelation.markingDefinitions
    );
    await Promise.all(markingDefinitionsPromises);
  }

  if (stixRelation.locations) {
    const createLocation = location =>
      wTx.query(
        `match $from id ${createdStixRelationId}; $to id ${location}; insert (localized: $from, location: $to) isa localization;`
      );
    const locationsPromises = map(createLocation, stixRelation.locations);
    await Promise.all(locationsPromises);
  }

  await wTx.commit();

  return getById(createdStixRelationId).then(created =>
    notify(BUS_TOPICS.StixRelation.ADDED_TOPIC, created, user)
  );
};

export const stixRelationDelete = stixRelationId => deleteById(stixRelationId);

export const stixRelationCleanContext = (user, stixRelationId) => {
  delEditContext(user, stixRelationId);
  return getById(stixRelationId).then(stixRelation =>
    notify(BUS_TOPICS.StixRelation.EDIT_TOPIC, stixRelation, user)
  );
};

export const stixRelationEditContext = (user, stixRelationId, input) => {
  setEditContext(user, stixRelationId, input);
  return getById(stixRelationId).then(stixRelation =>
    notify(BUS_TOPICS.StixRelation.EDIT_TOPIC, stixRelation, user)
  );
};

export const stixRelationEditField = (user, stixRelationId, input) =>
  updateAttribute(stixRelationId, input).then(stixRelation =>
    notify(BUS_TOPICS.StixRelation.EDIT_TOPIC, stixRelation, user)
  );

export const stixRelationAddRelation = (user, stixRelationId, input) => {
  const finalInput = pipe(
    assoc('fromId', stixRelationId),
    assoc('relationship_type', input.through)
  )(input);
  return addStixRelation(user, finalInput).then(relationData => {
    notify(BUS_TOPICS.StixDomainEntity.EDIT_TOPIC, relationData.node, user);
    return relationData;
  });
};
