import { ascend, assoc, descend, head, join, map, prop, sortWith, take } from 'ramda';
import { delEditContext, notify, setEditContext } from '../database/redis';
import {
  createRelation,
  deleteRelationById,
  distribution,
  escape,
  escapeString,
  executeWrite,
  getRelationInferredById,
  getSingleValueNumber,
  loadRelationById,
  loadRelationByStixId,
  paginateRelationships,
  prepareDate,
  updateAttribute
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';

export const findAll = async args => {
  const cacheArgs = assoc('canUseCache', true, args);
  return paginateRelationships(
    `match $rel($from, $to) isa ${args.relationType ? escape(args.relationType) : 'stix_relation'}`,
    cacheArgs
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
export const findById = stixRelationId => {
  if (stixRelationId.match(/[a-z-]+--[\w-]{36}/g)) {
    return loadRelationByStixId(stixRelationId);
  }
  if (stixRelationId.length !== 36) {
    return getRelationInferredById(stixRelationId);
  }
  return loadRelationById(stixRelationId);
};

// TODO @SAM  DELETE WITH GRAPHQL AND FRONT
export const findAllWithInferences = async args => {};
export const stixRelationsTimeSeriesWithInferences = async args => {};
export const stixRelationsDistributionWithInferences = async args => {};
// TODO @SAM  DELETE WITH GRAPHQL AND FRONT

export const stixRelationsDistribution = args => {
  const { limit = 10 } = args;
  return distribution(
    `match $rel($from, $x) isa ${args.relationType ? escape(args.relationType) : 'stix_relation'}; ${
      args.toTypes && args.toTypes.length > 0
        ? `${join(' ', map(toType => `{ $x isa ${escape(toType)}; } or`, args.toTypes))} { $x isa ${escape(
            head(args.toTypes)
          )}; };`
        : ''
    } ${args.fromId ? `$from has internal_id_key "${escapeString(args.fromId)}"` : '$from isa Stix-Domain-Entity'}`,
    args
  ).then(result => {
    if (args.order === 'asc') {
      return take(limit, sortWith([ascend(prop('value'))])(result));
    }
    return take(limit, sortWith([descend(prop('value'))])(result));
  });
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

// region mutations
export const addStixRelation = async (user, stixRelation, reversedReturn = false) => {
  const created = await createRelation(stixRelation.fromId, stixRelation, { reversedReturn });
  return notify(BUS_TOPICS.StixRelation.ADDED_TOPIC, created, user);
};
export const stixRelationDelete = async stixRelationId => {
  return deleteRelationById(stixRelationId);
};
export const stixRelationEditField = (user, stixRelationId, input) => {
  return executeWrite(wTx => {
    return updateAttribute(stixRelationId, input, wTx);
  }).then(async () => {
    const stixRelation = await loadRelationById(stixRelationId);
    return notify(BUS_TOPICS.StixRelation.EDIT_TOPIC, stixRelation, user);
  });
};
export const stixRelationAddRelation = (user, stixRelationId, input) => {
  return createRelation(stixRelationId, input).then(relationData => {
    notify(BUS_TOPICS.StixRelation.EDIT_TOPIC, relationData, user);
    return relationData;
  });
};
export const stixRelationDeleteRelation = async (user, stixRelationId, relationId) => {
  await deleteRelationById(relationId);
  const data = await loadRelationById(stixRelationId);
  return notify(BUS_TOPICS.StixRelation.EDIT_TOPIC, data, user);
};
// endregion

// region context
export const stixRelationCleanContext = (user, stixRelationId) => {
  delEditContext(user, stixRelationId);
  return loadRelationById(stixRelationId).then(stixRelation =>
    notify(BUS_TOPICS.StixRelation.EDIT_TOPIC, stixRelation, user)
  );
};
export const stixRelationEditContext = (user, stixRelationId, input) => {
  setEditContext(user, stixRelationId, input);
  return loadRelationById(stixRelationId).then(stixRelation =>
    notify(BUS_TOPICS.StixRelation.EDIT_TOPIC, stixRelation, user)
  );
};
// endregion
