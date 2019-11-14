import { delEditContext, notify, setEditContext } from '../database/redis';
import {
  createEntity,
  createRelation,
  deleteEntityById,
  deleteRelationById,
  escapeString,
  executeWrite,
  loadEntityById,
  paginate,
  TYPE_STIX_DOMAIN,
  updateAttribute
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';

export const findById = killChainPhaseId => {
  return loadEntityById(killChainPhaseId);
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
