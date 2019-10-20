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
  dropRepeats
} from 'ramda';
import { cursorToOffset } from 'graphql-relay/lib/connection/arrayconnection';
import uuid from 'uuid/v4';
import { delEditContext, setEditContext } from '../database/redis';
import {
  escape,
  escapeString,
  deleteById,
  updateAttribute,
  getById,
  getRelationById,
  getRelationInferredById,
  notify,
  graknNow,
  paginateRelationships,
  prepareDate,
  dayFormat,
  monthFormat,
  yearFormat,
  timeSeries,
  distribution,
  takeWriteTx,
  getObjects,
  getId,
  getSingleValueNumber,
  commitWriteTx,
  createRelation,
  deleteRelationById
} from '../database/grakn';
import { buildPagination } from '../database/utils';
import { BUS_TOPICS, logger } from '../config/conf';
import { deleteEntity } from '../database/elasticSearch';

const sumBy = attribute => vals => {
  return reduce(
    (current, val) => evolve({ [attribute]: add(val[attribute]) }, current),
    head(vals),
    tail(vals)
  );
};

const groupSumBy = curry((groupOn, sumOn, vals) =>
  values(map(sumBy(sumOn))(groupBy(prop(groupOn), vals)))
);

export const findAll = args => {
  return paginateRelationships(
    `match $rel($from, $to) isa ${
      args.relationType ? escape(args.relationType) : 'stix_relation'
    }`,
    args
  );
};

export const findByStixId = args => {
  return paginateRelationships(
    `match $rel($from, $to) isa relation; 
    $rel has stix_id_key "${escapeString(args.stix_id_key)}"`,
    args
  );
};

export const search = args => {
  return paginateRelationships(
    `match $rel($from, $to) isa relation;
    $to has name $name;
    $to has description $desc;
    { $name contains "${escapeString(args.search)}"; } or
    { $desc contains "${escapeString(args.search)}"; }`,
    args
  );
};

export const findAllWithInferences = async args => {
  const entities = await getObjects(
    `match $x isa entity; (${args.resolveRelationRole}: $from, $x) isa ${escape(
      args.resolveRelationType
    )};
    ${
      args.resolveRelationToTypes
        ? `${join(
            ' ',
            map(
              resolveRelationToType =>
                `{ $x isa ${escape(resolveRelationToType)}; } or`,
              args.resolveRelationToTypes
            )
          )} { $x isa ${escape(head(args.resolveRelationToTypes))}; };`
        : ''
    } $from has internal_id_key "${escapeString(args.fromId)}";
    get;`,
    'x',
    null,
    true
  );
  const fromIds = append(args.fromId, map(e => e.node.id, entities));
  const query = `match $rel($from, $to) isa ${
    args.relationType ? escape(args.relationType) : 'stix_relation'
  }; ${join(
    ' ',
    map(
      fromId => `{ $from has internal_id_key "${escapeString(fromId)}"; } or`,
      fromIds
    )
  )} { $from has internal_id_key "${escapeString(head(fromIds))}"; }`;
  const resultPromise = await paginateRelationships(
    query,
    assoc('inferred', false, omit(['fromId'], args)),
    null,
    !args.resolveViaTypes
  );
  if (args.resolveViaTypes) {
    const viaPromise = Promise.all(
      map(async resolveViaType => {
        const viaQuery = `match $from isa entity; $rel($from, $entity) isa ${
          args.relationType ? escape(args.relationType) : 'stix_relation'
        }; ${join(
          ' ',
          map(
            fromId => `{ $from has internal_id_key "${escapeString(fromId)}"; } or`,
            fromIds
          )
        )} { $from has internal_id_key "${escapeString(
          head(fromIds)
        )}"; }; $entity isa ${escape(
          resolveViaType.entityType
        )}; $link(${escape(
          resolveViaType.relationRole
        )}: $entity, $to) isa ${escape(resolveViaType.relationType)}`;
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
        `match $from isa entity; $rel($from, $entity) isa ${
          args.relationType ? escape(args.relationType) : 'stix_relation'
        }; ${join(
          ' ',
          map(
            fromId => `{ $from has internal_id_key "${escapeString(fromId)}"; } or`,
            fromIds
          )
        )} { $from has internal_id_key "${escapeString(
          head(fromIds)
        )}"; }; $link(${escape(
          resolveViaType.relationRole
        )}: $rel, $to) isa ${escape(resolveViaType.relationType)}`
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

export const stixRelationsTimeSeries = args => {
  return timeSeries(
    `match $x($from, $to) isa ${
      args.relationType ? escape(args.relationType) : 'stix_relation'
    }; ${
      args.toTypes && args.toTypes.length > 0
        ? `${join(
            ' ',
            map(toType => `{ $to isa ${escape(toType)}; } or`, args.toTypes)
          )} { $to isa ${escape(head(args.toTypes))}; };`
        : ''
    } ${
      args.fromId
        ? `$from has internal_id_key "${escapeString(args.fromId)}"`
        : '$from isa Stix-Domain-Entity'
    }`,
    args
  );
};

export const stixRelationsTimeSeriesWithInferences = async args => {
  const entities = await getObjects(
    `match $x isa entity; (${escape(
      args.resolveRelationRole
    )}: $from, $x) isa ${escape(args.resolveRelationType)}; ${
      args.resolveRelationToTypes
        ? `${join(
            ' ',
            map(
              resolveRelationToType =>
                `{ $x isa ${escape(resolveRelationToType)}; } or`,
              args.resolveRelationToTypes
            )
          )} { $x isa ${escape(head(args.resolveRelationToTypes))}; };`
        : ''
    } $from has internal_id_key "${escapeString(args.fromId)}"; get;`,
    'x',
    null,
    true
  );
  const fromIds = append(args.fromId, map(e => e.node.id, entities));
  const query = `match $x($from, $to) isa ${
    args.relationType ? escape(args.relationType) : 'stix_relation'
  }; ${join(
    ' ',
    map(
      fromId => `{ $from has internal_id_key "${escapeString(fromId)}"; } or`,
      fromIds
    )
  )} { $from has internal_id_key "${escapeString(head(fromIds))}"; }${
    args.toTypes && args.toTypes.length > 0
      ? `; ${join(
          ' ',
          map(toType => `{ $to isa ${escape(toType)}; } or`, args.toTypes)
        )} { $to isa ${escape(head(args.toTypes))}; }`
      : ''
  }`;
  const resultPromise = timeSeries(query, assoc('inferred', false, args));
  if (args.resolveViaTypes) {
    const viaPromise = Promise.all(
      map(resolveViaType => {
        const viaQuery = `match $from isa entity; $x($from, $entity) isa ${
          args.relationType ? escape(args.relationType) : 'stix_relation'
        }; ${join(
          ' ',
          map(
            fromId => `{ $from has internal_id_key "${escapeString(fromId)}"; } or`,
            fromIds
          )
        )} { $from has internal_id_key "${escapeString(
          head(fromIds)
        )}"; }; $entity isa ${escape(
          resolveViaType.entityType
        )}; $link(${escape(
          resolveViaType.relationRole
        )}: $entity, $to) isa ${escape(resolveViaType.relationType)} ${
          args.toTypes && args.toTypes.length > 0
            ? `; ${join(
                ' ',
                map(toType => `{ $to isa ${escape(toType)}; } or`, args.toTypes)
              )} { $to isa ${escape(head(args.toTypes))}; }`
            : ''
        }`;
        return timeSeries(viaQuery, assoc('inferred', true, args));
      })(args.resolveViaTypes)
    );
    const viaRelationQueries = map(
      resolveViaType =>
        `match $from isa entity; $x($from, $entity) isa ${
          args.relationType ? escape(args.relationType) : 'stix_relation'
        }; ${join(
          ' ',
          map(
            fromId => `{ $from has internal_id_key "${escapeString(fromId)}"; } or`,
            fromIds
          )
        )} { $from has internal_id_key "${escapeString(head(fromIds))}"; }; $link(${
          resolveViaType.relationRole
        }: $x, $to) isa ${escape(resolveViaType.relationType)} ${
          args.toTypes && args.toTypes.length > 0
            ? `; ${join(
                ' ',
                map(toType => `{ $to isa ${escape(toType)}; } or`, args.toTypes)
              )} { $to isa ${escape(head(args.toTypes))}; }`
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
      args.relationType ? escape(args.relationType) : 'stix_relation'
    }; ${
      args.toTypes && args.toTypes.length > 0
        ? `${join(
            ' ',
            map(toType => `{ $x isa ${escape(toType)}; } or`, args.toTypes)
          )} { $x isa ${escape(head(args.toTypes))}; };`
        : ''
    } ${
      args.fromId
        ? `$from has internal_id_key "${escapeString(args.fromId)}"`
        : '$from isa Stix-Domain-Entity'
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
  const entities = await getObjects(
    `match $x isa entity; (${escape(
      args.resolveRelationRole
    )}: $from, $x) isa ${escape(args.resolveRelationType)}; ${
      args.resolveRelationToTypes
        ? `${join(
            ' ',
            map(
              resolveRelationToType =>
                `{ $x isa ${escape(resolveRelationToType)}; } or`,
              args.resolveRelationToTypes
            )
          )} { $x isa ${escape(head(args.resolveRelationToTypes))}; };`
        : ''
    } $from has internal_id_key "${escapeString(args.fromId)}"; get;`,
    'x',
    null,
    true
  );
  const fromIds = append(args.fromId, map(e => e.node.id, entities));
  const query = `match $rel($from, $x) isa ${
    args.relationType ? escape(args.relationType) : 'stix_relation'
  }; ${join(
    ' ',
    map(
      fromId => `{ $from has internal_id_key "${escapeString(fromId)}"; } or`,
      fromIds
    )
  )} { $from has internal_id_key "${escapeString(head(fromIds))}"; }${
    args.toTypes && args.toTypes.length > 0
      ? `; ${join(
          ' ',
          map(toType => `{ $x isa ${escape(toType)}; } or`, args.toTypes)
        )} { $x isa ${escape(head(args.toTypes))}; }`
      : ''
  }`;
  const resultPromise = distribution(query, assoc('inferred', false, args));
  if (args.resolveViaTypes) {
    const viaPromise = Promise.all(
      map(resolveViaType => {
        const viaQuery = `match $from isa entity; $rel($from, $entity) isa ${
          args.relationType ? escape(args.relationType) : 'stix_relation'
        }; ${join(
          ' ',
          map(
            fromId => `{ $from has internal_id_key "${escapeString(fromId)}"; } or`,
            fromIds
          )
        )} { $from has internal_id_key "${escapeString(
          head(fromIds)
        )}"; }; $entity isa ${resolveViaType.entityType}; $link(${escape(
          resolveViaType.relationRole
        )}: $entity, $x) isa ${escape(resolveViaType.relationType)}; ${
          args.toTypes && args.toTypes.length > 0
            ? `${join(
                ' ',
                map(toType => `{ $x isa ${escape(toType)}; } or`, args.toTypes)
              )} { $x isa ${escape(head(args.toTypes))}; };`
            : ''
        } $rel has first_seen $o`;
        return distribution(viaQuery, assoc('inferred', true, args));
      })(args.resolveViaTypes)
    );
    const viaRelationQueries = map(
      resolveViaType =>
        `match $from isa entity; $rel($from, $entity) isa ${
          args.relationType ? escape(args.relationType) : 'stix_relation'
        }; ${join(
          ' ',
          map(
            fromId => `{ $from has internal_id_key "${escapeString(fromId)}"; } or`,
            fromIds
          )
        )} { $from has internal_id_key "${escapeString(
          head(fromIds)
        )}"; }; $link(${escape(
          resolveViaType.relationRole
        )}: $rel, $x) isa ${escape(resolveViaType.relationType)}; ${
          args.toTypes && args.toTypes.length > 0
            ? `${join(
                ' ',
                map(toType => `{ $x isa ${escape(toType)}; } or`, args.toTypes)
              )} { $x isa ${escape(head(args.toTypes))}; };`
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

export const stixRelationsNumber = args => ({
  count: getSingleValueNumber(
    `match $x($y, $z) isa ${args.type ? escape(args.type) : 'stix_relation'};
    ${
      args.endDate
        ? `$x has created_at $date;
    $date < ${prepareDate(args.endDate)};`
        : ''
    }
    ${args.fromId ? `$y has internal_id_key "${escapeString(args.fromId)}";` : ''}
    get;
    count;`,
    args.inferred ? args.inferred : false
  ),
  total: getSingleValueNumber(
    `match $x($y, $z) isa ${args.type ? escape(args.type) : 'stix_relation'};
    ${args.fromId ? `$y has internal_id_key "${escapeString(args.fromId)}";` : ''}
    get;
    count;`,
    args.inferred ? args.inferred : false
  )
});

export const findById = stixRelationId => getRelationById(stixRelationId);

export const findByIdInferred = stixRelationId => {
  return getRelationInferredById(stixRelationId);
};

export const addStixRelation = async (user, stixRelation) => {
  const wTx = await takeWriteTx();
  const internalId = stixRelation.internal_id_key
    ? escapeString(stixRelation.internal_id_key)
    : uuid();
  const query = `match $from has internal_id_key "${escapeString(
    stixRelation.fromId
  )}"; 
    $to has internal_id_key "${escapeString(stixRelation.toId)}"; 
    insert $stixRelation(${escape(stixRelation.fromRole)}: $from, ${escape(
    stixRelation.toRole
  )}: $to) 
    isa ${escape(stixRelation.relationship_type)}, 
    has internal_id_key "${internalId}",
    has relationship_type "${escapeString(
      stixRelation.relationship_type.toLowerCase()
    )}",
    has entity_type "stix-relation",
    has stix_id_key "${
      stixRelation.stix_id_key
        ? escapeString(stixRelation.stix_id_key)
        : `relationship--${uuid()}`
    }",
    has name "",
    has description "${escapeString(stixRelation.description)}",
    has role_played "${
      stixRelation.role_played
        ? escapeString(stixRelation.role_played)
        : 'Unknown'
    }",
    has weight ${stixRelation.weight ? escape(stixRelation.weight) : 0},
    has score ${stixRelation.score ? escape(stixRelation.score) : 50},
    ${
      stixRelation.expiration
        ? `has expiration ${prepareDate(stixRelation.expiration)},
          has expiration_day "${dayFormat(stixRelation.expiration)}",
          has expiration_month "${monthFormat(stixRelation.expiration)}",
          has expiration_year "${yearFormat(stixRelation.expiration)}",`
        : ''
    }
    has first_seen ${prepareDate(stixRelation.first_seen)},
    has first_seen_day "${dayFormat(stixRelation.first_seen)}",
    has first_seen_month "${monthFormat(stixRelation.first_seen)}",
    has first_seen_year "${yearFormat(stixRelation.first_seen)}",
    has last_seen ${prepareDate(stixRelation.last_seen)},
    has last_seen_day "${dayFormat(stixRelation.last_seen)}",
    has last_seen_month "${monthFormat(stixRelation.last_seen)}",
    has last_seen_year "${yearFormat(stixRelation.last_seen)}",
    has created ${
      stixRelation.created ? prepareDate(stixRelation.created) : graknNow()
    },
    has modified ${
      stixRelation.modified ? prepareDate(stixRelation.modified) : graknNow()
    },
    has revoked false,
    has created_at ${graknNow()},
    has created_at_day "${dayFormat(graknNow())}",
    has created_at_month "${monthFormat(graknNow())}",
    has created_at_year "${yearFormat(graknNow())}",        
    has updated_at ${graknNow()};
  `;
  logger.debug(`[GRAKN - infer: false] addStixRelation > ${query}`);
  const stixRelationIterator = await wTx.tx.query(query);
  const createStixRelation = await stixRelationIterator.next();
  const createdStixRelationId = await createStixRelation
    .map()
    .get('stixRelation').id;

  if (stixRelation.markingDefinitions) {
    const createMarkingDefinition = markingDefinition =>
      wTx.tx.query(
        `match $from id ${createdStixRelationId};
        $to has internal_id_key "${escapeString(markingDefinition)}";
        insert (so: $from, marking: $to) isa object_marking_refs, has internal_id_key "${uuid()}";`
      );
    const markingDefinitionsPromises = map(
      createMarkingDefinition,
      stixRelation.markingDefinitions
    );
    await Promise.all(markingDefinitionsPromises);
  }

  if (stixRelation.locations) {
    const createLocation = location =>
      wTx.tx.query(
        `match $from id ${createdStixRelationId};
        $to has internal_id_key "${escapeString(location)}";
        insert $rel(localized: $from, location: $to) isa localization, has internal_id_key "${uuid()}", 
        has stix_id_key "relationship--${uuid()}", has relationship_type 'localization', 
        has first_seen ${graknNow()}, has last_seen ${graknNow()}, has weight 3;`
      );
    const locationsPromises = map(createLocation, stixRelation.locations);
    await Promise.all(locationsPromises);
  }

  await commitWriteTx(wTx);

  return getRelationById(internalId).then(created => {
    return notify(BUS_TOPICS.StixRelation.ADDED_TOPIC, created, user);
  });
};

export const stixRelationDelete = async stixRelationId => {
  const graknId = await getId(stixRelationId);
  await deleteEntity('stix_relations', graknId);
  return deleteById(stixRelationId);
};

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
  updateAttribute(stixRelationId, input).then(stixRelation => {
    return notify(BUS_TOPICS.StixRelation.EDIT_TOPIC, stixRelation, user);
  });

export const stixRelationAddRelation = (user, stixRelationId, input) =>
  createRelation(stixRelationId, input).then(relationData => {
    notify(BUS_TOPICS.StixRelation.EDIT_TOPIC, relationData.node, user);
    return relationData;
  });

export const stixRelationDeleteRelation = (user, stixRelationId, relationId) =>
  deleteRelationById(stixRelationId, relationId).then(relationData => {
    notify(BUS_TOPICS.StixRelation.EDIT_TOPIC, relationData.node, user);
    return relationData;
  });
