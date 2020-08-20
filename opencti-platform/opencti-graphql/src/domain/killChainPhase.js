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
import { ENTITY_TYPE_KILL_CHAIN_PHASE, RELATION_KILL_CHAIN_PHASE } from '../utils/idGenerator';

export const findById = (killChainPhaseId) => {
  return loadEntityById(killChainPhaseId, ENTITY_TYPE_KILL_CHAIN_PHASE);
};

export const findAll = (args) => {
  return listEntities([ENTITY_TYPE_KILL_CHAIN_PHASE], ['kill_chain_name', 'phase_name'], args);
};

export const addKillChainPhase = async (user, killChainPhase) => {
  const phaseOrder = killChainPhase.x_opencti_order ? killChainPhase.x_opencti_order : 0;
  const killChainPhaseToCreate = assoc('x_opencti_order', phaseOrder, killChainPhase);
  const created = await createEntity(user, killChainPhaseToCreate, ENTITY_TYPE_KILL_CHAIN_PHASE, {
    noLog: true,
  });
  return notify(BUS_TOPICS[ENTITY_TYPE_KILL_CHAIN_PHASE].ADDED_TOPIC, created, user);
};

export const killChainPhaseDelete = (user, killChainPhaseId) => {
  return deleteEntityById(user, killChainPhaseId, ENTITY_TYPE_KILL_CHAIN_PHASE, { noLog: true });
};

export const killChainPhaseAddRelation = (user, killChainPhaseId, input) => {
  const finalInput = pipe(
    assoc('toId', killChainPhaseId),
    assoc('relationship_type', RELATION_KILL_CHAIN_PHASE)
  )(input);
  return createRelation(user, finalInput).then((relationData) => {
    notify(BUS_TOPICS[ENTITY_TYPE_KILL_CHAIN_PHASE].EDIT_TOPIC, relationData, user);
    return relationData;
  });
};

export const killChainPhaseDeleteRelation = async (user, killChainPhaseId, relationId) => {
  await deleteRelationById(user, relationId, RELATION_KILL_CHAIN_PHASE);
  const data = await loadEntityById(killChainPhaseId, ENTITY_TYPE_KILL_CHAIN_PHASE);
  return notify(BUS_TOPICS[ENTITY_TYPE_KILL_CHAIN_PHASE].EDIT_TOPIC, data, user);
};

export const killChainPhaseEditField = (user, killChainPhaseId, input) => {
  return executeWrite((wTx) => {
    return updateAttribute(user, killChainPhaseId, ENTITY_TYPE_KILL_CHAIN_PHASE, input, wTx, { noLog: true });
  }).then(async () => {
    const killChainPhase = await loadEntityById(killChainPhaseId, ENTITY_TYPE_KILL_CHAIN_PHASE);
    return notify(BUS_TOPICS[ENTITY_TYPE_KILL_CHAIN_PHASE].EDIT_TOPIC, killChainPhase, user);
  });
};

export const killChainPhaseCleanContext = async (user, killChainPhaseId) => {
  await delEditContext(user, killChainPhaseId);
  return loadEntityById(killChainPhaseId, ENTITY_TYPE_KILL_CHAIN_PHASE).then((killChainPhase) =>
    notify(BUS_TOPICS[ENTITY_TYPE_KILL_CHAIN_PHASE].EDIT_TOPIC, killChainPhase, user)
  );
};

export const killChainPhaseEditContext = async (user, killChainPhaseId, input) => {
  await setEditContext(user, killChainPhaseId, input);
  return loadEntityById(killChainPhaseId, ENTITY_TYPE_KILL_CHAIN_PHASE).then((killChainPhase) =>
    notify(BUS_TOPICS[ENTITY_TYPE_KILL_CHAIN_PHASE].EDIT_TOPIC, killChainPhase, user)
  );
};
