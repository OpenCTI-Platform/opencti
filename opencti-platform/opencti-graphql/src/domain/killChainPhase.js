import uuid from 'uuid/v4';
import { delEditContext, notify, setEditContext } from '../database/redis';
import {
  createRelation,
  dayFormat,
  deleteEntityById,
  deleteRelationById,
  escape,
  escapeString,
  executeWrite,
  graknNow,
  loadEntityById,
  monthFormat,
  paginate,
  prepareDate,
  updateAttribute,
  yearFormat
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { addCreatedByRef, addMarkingDefs } from './stixEntity';
import { elLoadById } from '../database/elasticSearch';

export const findById = killChainPhaseId => {
  return elLoadById(killChainPhaseId);
};

// region grakn fetch
export const findAll = args => {
  return paginate(
    `match $k isa Kill-Chain-Phase ${
      args.search
        ? `; $k has kill_chain_name $name;
   $k has phase_name $phase;
   { $name contains "${escapeString(args.search)}"; } or
   { $phase contains "${escapeString(args.search)}"; }`
        : ''
    }`,
    args
  );
};
export const findByEntity = args => {
  return paginate(
    `match $k isa Kill-Chain-Phase; 
    $rel(kill_chain_phase:$k, phase_belonging:$so) isa kill_chain_phases; 
    $so has internal_id_key "${escapeString(args.objectId)}"`,
    args
  );
};
export const findByPhaseName = args => {
  return paginate(
    `match $k isa Kill-Chain-Phase; 
    $k has phase_name "${escapeString(args.phaseName)}"`,
    args,
    false
  );
};
// endregion

export const addKillChainPhase = async (user, killChainPhase) => {
  const internalId = killChainPhase.internal_id_key ? escapeString(killChainPhase.internal_id_key) : uuid();
  await executeWrite(async wTx => {
    const now = graknNow();
    const killChainPhaseIterator = await wTx.tx.query(`insert $killChainPhase isa Kill-Chain-Phase,
    has internal_id_key "${internalId}",
    has entity_type "kill-chain-phase",
    has stix_id_key "${
      killChainPhase.stix_id_key ? escapeString(killChainPhase.stix_id_key) : `kill-chain-phase--${uuid()}`
    }",
    has kill_chain_name "${escapeString(killChainPhase.kill_chain_name)}",
    has phase_name "${escapeString(killChainPhase.phase_name)}",
    has phase_order ${escape(killChainPhase.phase_order)},
    has created ${killChainPhase.created ? prepareDate(killChainPhase.created) : now},
    has modified ${killChainPhase.modified ? prepareDate(killChainPhase.modified) : now},
    has revoked false,
    has created_at ${now},
    has created_at_day "${dayFormat(now)}",
    has created_at_month "${monthFormat(now)}",
    has created_at_year "${yearFormat(now)}",       
    has updated_at ${now};
  `);
    const createKillChainPhase = await killChainPhaseIterator.next();
    return createKillChainPhase.map().get('killChainPhase').id;
  });
  const created = await loadEntityById(internalId);
  await addCreatedByRef(internalId, killChainPhase.createdByRef);
  await addMarkingDefs(internalId, killChainPhase.markingDefinitions);
  return notify(BUS_TOPICS.KillChainPhase.ADDED_TOPIC, created, user);
};

export const killChainPhaseDelete = killChainPhaseId => {
  return deleteEntityById(killChainPhaseId);
};
export const killChainPhaseAddRelation = (user, killChainPhaseId, input) => {
  return createRelation(killChainPhaseId, input).then(relationData => {
    notify(BUS_TOPICS.KillChainPhase.EDIT_TOPIC, relationData.node, user);
    return relationData;
  });
};
export const killChainPhaseDeleteRelation = (user, killChainPhaseId, relationId) => {
  return deleteRelationById(killChainPhaseId, relationId).then(relationData => {
    notify(BUS_TOPICS.KillChainPhase.EDIT_TOPIC, relationData.node, user);
    return relationData;
  });
};
export const killChainPhaseEditField = (user, killChainPhaseId, input) => {
  return executeWrite(wTx => {
    return updateAttribute(killChainPhaseId, input, wTx);
  }).then(async () => {
    const killChainPhase = await elLoadById(killChainPhaseId);
    return notify(BUS_TOPICS.KillChainPhase.EDIT_TOPIC, killChainPhase, user);
  });
};

export const killChainPhaseCleanContext = (user, killChainPhaseId) => {
  delEditContext(user, killChainPhaseId);
  return loadEntityById(killChainPhaseId).then(killChainPhase =>
    notify(BUS_TOPICS.KillChainPhase.EDIT_TOPIC, killChainPhase, user)
  );
};
export const killChainPhaseEditContext = (user, killChainPhaseId, input) => {
  setEditContext(user, killChainPhaseId, input);
  return loadEntityById(killChainPhaseId).then(killChainPhase =>
    notify(BUS_TOPICS.KillChainPhase.EDIT_TOPIC, killChainPhase, user)
  );
};
