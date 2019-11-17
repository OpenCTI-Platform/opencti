import { assoc, map } from 'ramda';
import uuid from 'uuid/v4';
import {
  findAll as stixRelationFindAll,
  findByStixId as stixRelationFindByStixId,
  search as searchStixRelations,
  findAllWithInferences as findAllWithInferencesStixRelations,
  findById as findByIdStixRelation,
  findByIdInferred as findByIdInferredStixRelation,
  stixRelationDelete,
  stixRelationCleanContext,
  stixRelationEditContext,
  stixRelationEditField,
  stixRelationAddRelation,
  stixRelationDeleteRelation
} from './stixRelation';
import {
  dayFormat,
  escape,
  escapeString,
  executeWrite,
  getRelationById,
  graknNow,
  monthFormat,
  notify,
  prepareDate,
  yearFormat
} from '../database/grakn';
import { BUS_TOPICS, logger } from '../config/conf';

export const findAll = args =>
  stixRelationFindAll(
    args.relationType
      ? args
      : assoc('relationType', 'stix_observable_relation', args)
  );

export const findByStixId = args => stixRelationFindByStixId(args);

export const search = args =>
  searchStixRelations(
    args.relationType
      ? args
      : assoc('relationType', 'stix_observable_relation', args)
  );

export const findAllWithInferences = async args =>
  findAllWithInferencesStixRelations(
    args.relationType
      ? args
      : assoc('relationType', 'stix_observable_relation', args)
  );

export const findById = stixObservableRelationId =>
  findByIdStixRelation(stixObservableRelationId);

export const findByIdInferred = stixObservableRelationId => {
  return findByIdInferredStixRelation(stixObservableRelationId);
};

export const addStixObservableRelation = async (
  user,
  stixObservableRelation
) => {
  const stixObservableRelationId = await executeWrite(async wTx => {
    const internalId = stixObservableRelation.internal_id_key
      ? escapeString(stixObservableRelation.internal_id_key)
      : uuid();
    const query = `match $from has internal_id_key "${escapeString(
      stixObservableRelation.fromId
    )}"; 
    $to has internal_id_key "${escapeString(stixObservableRelation.toId)}"; 
    insert $stixRelation(${escape(
      stixObservableRelation.fromRole
    )}: $from, ${escape(stixObservableRelation.toRole)}: $to) 
    isa ${escape(stixObservableRelation.relationship_type)}, 
    has internal_id_key "${internalId}",
    has relationship_type "${escapeString(
      stixObservableRelation.relationship_type.toLowerCase()
    )}",
    has entity_type "stix-relation",
    has role_played "${
      stixObservableRelation.role_played
        ? escapeString(stixObservableRelation.role_played)
        : 'Unknown'
    }",
    has first_seen ${prepareDate(stixObservableRelation.first_seen)},
    has first_seen_day "${dayFormat(stixObservableRelation.first_seen)}",
    has first_seen_month "${monthFormat(stixObservableRelation.first_seen)}",
    has first_seen_year "${yearFormat(stixObservableRelation.first_seen)}",
    has last_seen ${prepareDate(stixObservableRelation.last_seen)},
    has last_seen_day "${dayFormat(stixObservableRelation.last_seen)}",
    has last_seen_month "${monthFormat(stixObservableRelation.last_seen)}",
    has last_seen_year "${yearFormat(stixObservableRelation.last_seen)}",
    has created ${
      stixObservableRelation.created
        ? prepareDate(stixObservableRelation.created)
        : graknNow()
    },
    has modified ${
      stixObservableRelation.modified
        ? prepareDate(stixObservableRelation.modified)
        : graknNow()
    },
    has revoked false,
    has created_at ${graknNow()},
    has created_at_day "${dayFormat(graknNow())}",
    has created_at_month "${monthFormat(graknNow())}",
    has created_at_year "${yearFormat(graknNow())}",        
    has updated_at ${graknNow()};
  `;
    logger.debug(`[GRAKN - infer: false] addStixObservableRelation > ${query}`);
    await wTx.tx.query(query);
    return internalId;
  });
  return getRelationById(stixObservableRelationId).then(created => {
    return notify(BUS_TOPICS.StixRelation.ADDED_TOPIC, created, user);
  });
};

export const stixObservableRelationDelete = async stixObservableRelationId =>
  stixRelationDelete(stixObservableRelationId);

export const stixObservableRelationCleanContext = (
  user,
  stixObservableRelationId
) => stixRelationCleanContext(user, stixObservableRelationId);

export const stixObservableRelationEditContext = (
  user,
  stixObservableRelationId,
  input
) => stixRelationEditContext(user, stixObservableRelationId, input);

export const stixObservableRelationEditField = (
  user,
  stixObservableRelationId,
  input
) => stixRelationEditField(user, stixObservableRelationId, input);

export const stixObservableRelationAddRelation = (
  user,
  stixObservableRelationId,
  input
) => stixRelationAddRelation(user, stixObservableRelationId, input);

export const stixObservableRelationDeleteRelation = (
  user,
  stixObservableRelationId,
  relationId
) => stixRelationDeleteRelation(user, stixObservableRelationId, relationId);
