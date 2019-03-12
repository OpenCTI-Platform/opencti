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
  mergeWith,
  evolve,
  tail,
  curry,
  values,
  prop,
  groupBy,
  reduce,
  add
} from 'ramda';
import { cursorToOffset } from 'graphql-relay/lib/connection/arrayconnection';
import uuid from 'uuid/v4';
import { delEditContext, setEditContext } from '../database/redis';
import {
  deleteOneById,
  editInputTx,
  loadByID,
  loadRelationById,
  loadRelationInferredById,
  notify,
  now,
  paginateRelationships,
  paginate,
  prepareDate,
  dayFormat,
  monthFormat,
  yearFormat,
  prepareString,
  timeSeries,
  distribution,
  takeTx,
  qkObjSimple,
  buildPaginationRelationships
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

export const findAllWithInferences = async args => {
  const entities = await qkObjSimple(
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
  const resultPromise = paginateRelationships(
    query,
    assoc('inferred', false, omit(['fromId'], args)),
    null,
    false
  );
  let viaPromise = Promise.resolve([{ globalCount: 0, instances: [] }]);
  if (args.resolveViaTypes) {
    viaPromise = Promise.all(
      map(resolveViaType => {
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
  }

  return Promise.all([resultPromise, viaPromise]).then(([result, via]) => {
    const { first = 200, after } = args;
    const offset = after ? cursorToOffset(after) : 0;
    const globalCount = result.globalCount + sum(pluck('globalCount', via));
    let viaInstances = [];
    forEach(n => {
      viaInstances = concat(viaInstances, n.instances);
    }, via);
    const instances = concat(result.instances, viaInstances);
    return buildPaginationRelationships(first, offset, instances, globalCount);
  });
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
  const entities = await qkObjSimple(
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
  )} { $from id ${head(fromIds)}; }; ${
    args.toTypes
      ? `${join(
          ' ',
          map(toType => `{ $x isa ${toType}; } or`, args.toTypes)
        )} { $x isa ${head(args.toTypes)}; }`
      : ''
  }`;
  const resultPromise = timeSeries(
    query,
    assoc('inferred', false, omit(['fromId'], args))
  );
  let viaPromise = Promise.resolve([]);
  if (args.resolveViaTypes) {
    viaPromise = Promise.all(
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
              )} { $x isa ${head(args.toTypes)}; }`
            : ''
        }`;
        return timeSeries(viaQuery, omit(['fromId'], args));
      })(args.resolveViaTypes)
    );
  }

  return Promise.all([resultPromise, viaPromise]).then(([result, via]) => {
    let viaResult = [];
    forEach(n => {
      viaResult = concat(viaResult, n);
    }, via);
    const finalResult = concat(result, viaResult);
    return groupSumBy('date', 'value', finalResult);
  });
};

export const stixRelationsDistribution = args =>
  distribution(
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
  );

export const stixRelationsDistributionWithInferences = async args => {
  const entities = await qkObjSimple(
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
  )} { $from id ${head(fromIds)}; }; ${
    args.toTypes
      ? `${join(
          ' ',
          map(toType => `{ $x isa ${toType}; } or`, args.toTypes)
        )} { $x isa ${head(args.toTypes)}; }`
      : ''
  }`;
  const resultPromise = distribution(
    query,
    assoc('inferred', false, omit(['fromId'], args))
  );
  let viaPromise = Promise.resolve([]);
  if (args.resolveViaTypes) {
    viaPromise = Promise.all(
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
              )} { $x isa ${head(args.toTypes)}; }`
            : ''
        }`;
        return distribution(viaQuery, omit(['fromId'], args));
      })(args.resolveViaTypes)
    );
  }

  return Promise.all([resultPromise, viaPromise]).then(([result, via]) => {
    let viaResult = [];
    forEach(n => {
      viaResult = concat(viaResult, n);
    }, via);
    const finalResult = concat(result, viaResult);
    return groupSumBy('label', 'value', finalResult);
  });
};

export const findById = stixRelationId => loadRelationById(stixRelationId);
export const findByIdInferred = stixRelationId =>
  loadRelationInferredById(stixRelationId);

export const search = args =>
  paginateRelationships(
    `match $m isa Stix-Domain-Entity
    has name_lowercase $name
    has description_lowercase $desc;
    { $name contains "${prepareString(args.search.toLowerCase())}"; } or
    { $desc contains "${prepareString(args.search.toLowerCase())}"; }`,
    args
  );

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
  const wTx = await takeTx();
  const stixRelationIterator = await wTx.query(`match $from id ${
    stixRelation.fromId
  }; 
    $to id ${stixRelation.toId}; 
    insert $stixRelation(${stixRelation.fromRole}: $from, ${
    stixRelation.toRole
  }: $to) 
    isa ${stixRelation.relationship_type} 
    has relationship_type "${stixRelation.relationship_type.toLowerCase()}";
    $stixRelation has type "stix-relation";
    $stixRelation has stix_id "relationship--${uuid()}";
    $stixRelation has name "";
    $stixRelation has description "${prepareString(stixRelation.description)}";
    $stixRelation has name_lowercase "";
    $stixRelation has description_lowercase "${
      stixRelation.description
        ? prepareString(stixRelation.description.toLowerCase())
        : ''
    }";
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
    $stixRelation has created ${now()};
    $stixRelation has modified ${now()};
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

  return loadByID(createdStixRelationId).then(created =>
    notify(BUS_TOPICS.StixRelation.ADDED_TOPIC, created, user)
  );
};

export const stixRelationDelete = stixRelationId =>
  deleteOneById(stixRelationId);

export const stixRelationCleanContext = (user, stixRelationId) => {
  delEditContext(user, stixRelationId);
  return loadByID(stixRelationId).then(stixRelation =>
    notify(BUS_TOPICS.StixRelation.EDIT_TOPIC, stixRelation, user)
  );
};

export const stixRelationEditContext = (user, stixRelationId, input) => {
  setEditContext(user, stixRelationId, input);
  return loadByID(stixRelationId).then(stixRelation =>
    notify(BUS_TOPICS.StixRelation.EDIT_TOPIC, stixRelation, user)
  );
};

export const stixRelationEditField = (user, stixRelationId, input) =>
  editInputTx(stixRelationId, input).then(stixRelation =>
    notify(BUS_TOPICS.StixRelation.EDIT_TOPIC, stixRelation, user)
  );
