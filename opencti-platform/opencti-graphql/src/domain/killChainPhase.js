import { assoc } from 'ramda';
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
  updateAttribute
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';

export const findById = killChainPhaseId => {
  return loadEntityById(killChainPhaseId);
};

export const findAll = args => {
  const typedArgs = assoc('types', ['Kill-Chain-Phase'], args);
  return listEntities(['kill_chain_name', 'phase_name'], typedArgs);
};

export const addKillChainPhase = async (user, killChainPhase) => {
  const created = await createEntity(killChainPhase, 'Kill-Chain-Phase', TYPE_STIX_DOMAIN);
  return notify(BUS_TOPICS.KillChainPhase.ADDED_TOPIC, created, user);
};

export const killChainPhaseDelete = killChainPhaseId => {
  return deleteEntityById(killChainPhaseId);
};
export const killChainPhaseAddRelation = (user, killChainPhaseId, input) => {
  return createRelation(killChainPhaseId, input).then(relationData => {
    notify(BUS_TOPICS.KillChainPhase.EDIT_TOPIC, relationData, user);
    return relationData;
  });
};
export const killChainPhaseDeleteRelation = (user, killChainPhaseId, relationId) => {
  return deleteRelationById(killChainPhaseId, relationId).then(relationData => {
    notify(BUS_TOPICS.KillChainPhase.EDIT_TOPIC, relationData, user);
    return relationData;
  });
};
export const killChainPhaseEditField = (user, killChainPhaseId, input) => {
  return executeWrite(wTx => {
    return updateAttribute(killChainPhaseId, input, wTx);
  }).then(async () => {
    const killChainPhase = await loadEntityById(killChainPhaseId);
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
