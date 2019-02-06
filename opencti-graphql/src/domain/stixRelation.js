import { head, join, map } from 'ramda';
import uuid from 'uuid/v4';
import { delEditContext, setEditContext } from '../database/redis';
import {
  deleteOneById,
  editInputTx,
  loadByID,
  loadRelationById,
  notify,
  now,
  paginateRelationships,
  paginate,
  qk,
  prepareDate,
  dayFormat,
  monthFormat,
  yearFormat,
  prepareString,
  timeSeries,
  distribution
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';

export const findAll = args =>
  paginateRelationships('match $rel($from, $to) isa stix_relation', args);

export const stixRelationsTimeSeries = args =>
  timeSeries(
    `match $x($from, $to) isa stix_relation;  ${
      args.toTypes
        ? `${join(
            ' ',
            map(toType => `{ $to isa ${toType}; } or`, args.toTypes)
          )} { $to isa ${head(args.toTypes)}; };`
        : ''
    } $from id ${args.fromId}`,
    args
  );

export const stixRelationsDistribution = args =>
  distribution(
    `match $rel($from, $x) isa stix_relation; ${
      args.toTypes
        ? `${join(
            ' ',
            map(toType => `{ $x isa ${toType}; } or`, args.toTypes)
          )} { $x isa ${head(args.toTypes)}; };`
        : ''
    } $from id ${args.fromId}`,
    args
  );

export const findByType = args =>
  paginateRelationships(
    `match $rel($from, $to) isa ${args.relationType}`,
    args
  );

export const stixRelationsTimeSeriesByType = args =>
  timeSeries(
    `match $x($from, $to) isa ${args.relationType}; ${
      args.toTypes
        ? `${join(
            ' ',
            map(toType => `{ $to isa ${toType}; } or`, args.toTypes)
          )} { $to isa ${head(args.toTypes)}; };`
        : ''
    } $from id ${args.fromId}`,
    args
  );

export const stixRelationDistributionByType = args =>
  distribution(
    `match $rel($from, $x) isa ${args.relationType}; ${
      args.toTypes
        ? `${join(
            ' ',
            map(toType => `{ $x isa ${toType}; } or`, args.toTypes)
          )} { $x isa ${head(args.toTypes)}; };`
        : ''
    } $from id ${args.fromId}`,
    args
  );

export const findById = stixRelationId => loadRelationById(stixRelationId);

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

export const addStixRelation = async (user, stixRelation) => {
  const createStixRelation = qk(`match $from id ${stixRelation.fromId}; 
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
  return createStixRelation.then(result => {
    const { data } = result;
    return loadByID(head(data).stixRelation.id).then(created =>
      notify(BUS_TOPICS.StixRelation.ADDED_TOPIC, created, user)
    );
  });
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
