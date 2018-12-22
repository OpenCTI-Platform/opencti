import { head } from 'ramda';
import uuid from 'uuid/v4';
import { delEditContext, setEditContext } from '../database/redis';
import {
  createRelation,
  deleteByID,
  editInputTx,
  loadByID,
  notify,
  now,
  paginate,
  qk
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';

export const findAll = args => paginate('match $m isa Kill-Chain-Phase', args);

export const markingDefinitions = (killChainPhaseId, args) =>
  paginate(
    `match $marking isa Marking-Definition; 
    (marking:$marking, so:$killChainPhase) isa object_marking_refs; 
    $killChainPhase id ${killChainPhaseId}`,
    args
  );

export const findById = killChainPhaseId => loadByID(killChainPhaseId);

export const addKillChainPhase = async (user, killChainPhase) => {
  const createKillChainPhase = qk(`insert $killChainPhase isa Kill-Chain-Phase
    has type "kill-chain-phase";
    $killChainPhase has stix_id "kill-chain-phase--${uuid()}";
    $killChainPhase has kill_chain_name "${killChainPhase.kill_chain_name}";
    $killChainPhase has phase_name "${killChainPhase.phase_name}";
    $killChainPhase has phase_order "${killChainPhase.phase_order}";
    $killChainPhase has created ${now()};
    $killChainPhase has modified ${now()};
    $killChainPhase has revoked false;
    $killChainPhase has created_at ${now()};
    $killChainPhase has updated_at ${now()};
  `);
  return createKillChainPhase.then(result => {
    const { data } = result;
    return findById(head(data).killChainPhase.id).then(created =>
      notify(BUS_TOPICS.KillChainPhase.ADDED_TOPIC, created)
    );
  });
};

export const killChainPhaseDelete = killChainPhaseId =>
  deleteByID(killChainPhaseId);

export const killChainPhaseDeleteRelation = relationId =>
  deleteByID(relationId);

export const killChainPhaseAddRelation = (killChainPhaseId, input) =>
  createRelation(killChainPhaseId, input).then(killChainPhase =>
    notify(BUS_TOPICS.KillChainPhase.EDIT_TOPIC, killChainPhase)
  );

export const killChainPhaseCleanContext = (user, killChainPhaseId) => {
  delEditContext(user, killChainPhaseId);
  return findById(killChainPhaseId).then(killChainPhase =>
    notify(BUS_TOPICS.KillChainPhase.EDIT_TOPIC, killChainPhase)
  );
};

export const killChainPhaseEditContext = (user, killChainPhaseId, input) => {
  setEditContext(user, killChainPhaseId, input);
  findById(killChainPhaseId).then(killChainPhase =>
    notify(BUS_TOPICS.KillChainPhase.EDIT_TOPIC, killChainPhase)
  );
};

export const killChainPhaseEditField = (killChainPhaseId, input) =>
  editInputTx(killChainPhaseId, input).then(killChainPhase =>
    notify(BUS_TOPICS.KillChainPhase.EDIT_TOPIC, killChainPhase)
  );
