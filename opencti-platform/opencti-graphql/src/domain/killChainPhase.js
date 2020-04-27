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
  TYPE_STIX_DOMAIN,
  updateAttribute,
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';

export const findById = (killChainPhaseId) => {
  return loadEntityById(killChainPhaseId, 'Kill-Chain-Phase');
};

export const findAll = (args) => {
  return listEntities(['Kill-Chain-Phase'], ['kill_chain_name', 'phase_name'], args);
};

export const addKillChainPhase = async (user, killChainPhase) => {
  const killChainPhaseToCreate = assoc(
    'phase_order',
    killChainPhase.phase_order ? killChainPhase.phase_order : 0,
    killChainPhase
  );
  const created = await createEntity(user, killChainPhaseToCreate, 'Kill-Chain-Phase', {
    modelType: TYPE_STIX_DOMAIN,
    noLog: true,
  });
  return notify(BUS_TOPICS.KillChainPhase.ADDED_TOPIC, created, user);
};

export const killChainPhaseDelete = (user, killChainPhaseId) => {
  return deleteEntityById(user, killChainPhaseId, 'Kill-Chain-Phase', { noLog: true });
};
export const killChainPhaseAddRelation = (user, killChainPhaseId, input) => {
  const finalInput = pipe(assoc('through', 'kill_chain_phases'), assoc('toType', 'kill_chain_phases'))(input);
  return createRelation(user, killChainPhaseId, finalInput).then((relationData) => {
    notify(BUS_TOPICS.KillChainPhase.EDIT_TOPIC, relationData, user);
    return relationData;
  });
};
export const killChainPhaseDeleteRelation = async (user, killChainPhaseId, relationId) => {
  await deleteRelationById(user, relationId, 'stix_relation_embedded');
  const data = await loadEntityById(killChainPhaseId, 'Kill-Chain-Phase');
  return notify(BUS_TOPICS.KillChainPhase.EDIT_TOPIC, data, user);
};
export const killChainPhaseEditField = (user, killChainPhaseId, input) => {
  return executeWrite((wTx) => {
    return updateAttribute(user, killChainPhaseId, 'Kill-Chain-Phase', input, wTx, { noLog: true });
  }).then(async () => {
    const killChainPhase = await loadEntityById(killChainPhaseId, 'Kill-Chain-Phase');
    return notify(BUS_TOPICS.KillChainPhase.EDIT_TOPIC, killChainPhase, user);
  });
};

export const killChainPhaseCleanContext = (user, killChainPhaseId) => {
  delEditContext(user, killChainPhaseId);
  return loadEntityById(killChainPhaseId, 'Kill-Chain-Phase').then((killChainPhase) =>
    notify(BUS_TOPICS.KillChainPhase.EDIT_TOPIC, killChainPhase, user)
  );
};
export const killChainPhaseEditContext = (user, killChainPhaseId, input) => {
  setEditContext(user, killChainPhaseId, input);
  return loadEntityById(killChainPhaseId, 'Kill-Chain-Phase').then((killChainPhase) =>
    notify(BUS_TOPICS.KillChainPhase.EDIT_TOPIC, killChainPhase, user)
  );
};
