import { pipe, assoc } from 'ramda';
import { delEditContext, notify, setEditContext } from '../database/redis';
import {
  createEntity,
  createRelation,
  deleteEntityById,
  deleteRelationById,
  executeWrite,
  listEntities,
  loadEntityById,
  updateAttribute,
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import {ENTITY_TYPE_KILL_CHAIN, RELATION_KILL_CHAIN_PHASE} from "../utils/idGenerator";

export const findById = (killChainPhaseId) => {
  return loadEntityById(killChainPhaseId, ENTITY_TYPE_KILL_CHAIN);
};

export const findAll = (args) => {
  return listEntities([ENTITY_TYPE_KILL_CHAIN], ['kill_chain_name', 'phase_name'], args);
};

export const addKillChainPhase = async (user, killChainPhase) => {
  const phaseOrder = killChainPhase.phase_order ? killChainPhase.phase_order : 0;
  const killChainPhaseToCreate = assoc('phase_order', phaseOrder, killChainPhase);
  const created = await createEntity(user, killChainPhaseToCreate, ENTITY_TYPE_KILL_CHAIN, {
    noLog: true,
  });
  return notify(BUS_TOPICS.KillChainPhase.ADDED_TOPIC, created, user);
};

export const killChainPhaseDelete = (user, killChainPhaseId) => {
  return deleteEntityById(user, killChainPhaseId, ENTITY_TYPE_KILL_CHAIN, { noLog: true });
};
export const killChainPhaseAddRelation = (user, killChainPhaseId, input) => {
  const finalInput = pipe(
    assoc('fromId', killChainPhaseId),
    assoc('through', RELATION_KILL_CHAIN_PHASE),
    assoc('toType', ENTITY_TYPE_KILL_CHAIN) // TODO @SAM CHECK?
  )(input);
  return createRelation(user, finalInput).then((relationData) => {
    notify(BUS_TOPICS.KillChainPhase.EDIT_TOPIC, relationData, user);
    return relationData;
  });
};
export const killChainPhaseDeleteRelation = async (user, killChainPhaseId, relationId) => {
  await deleteRelationById(user, relationId, 'stix_relation_embedded');
  const data = await loadEntityById(killChainPhaseId, ENTITY_TYPE_KILL_CHAIN);
  return notify(BUS_TOPICS.KillChainPhase.EDIT_TOPIC, data, user);
};
export const killChainPhaseEditField = (user, killChainPhaseId, input) => {
  return executeWrite((wTx) => {
    return updateAttribute(user, killChainPhaseId, ENTITY_TYPE_KILL_CHAIN, input, wTx, { noLog: true });
  }).then(async () => {
    const killChainPhase = await loadEntityById(killChainPhaseId, ENTITY_TYPE_KILL_CHAIN);
    return notify(BUS_TOPICS.KillChainPhase.EDIT_TOPIC, killChainPhase, user);
  });
};

export const killChainPhaseCleanContext = (user, killChainPhaseId) => {
  delEditContext(user, killChainPhaseId);
  return loadEntityById(killChainPhaseId, ENTITY_TYPE_KILL_CHAIN).then((killChainPhase) =>
    notify(BUS_TOPICS.KillChainPhase.EDIT_TOPIC, killChainPhase, user)
  );
};
export const killChainPhaseEditContext = (user, killChainPhaseId, input) => {
  setEditContext(user, killChainPhaseId, input);
  return loadEntityById(killChainPhaseId, ENTITY_TYPE_KILL_CHAIN).then((killChainPhase) =>
    notify(BUS_TOPICS.KillChainPhase.EDIT_TOPIC, killChainPhase, user)
  );
};
