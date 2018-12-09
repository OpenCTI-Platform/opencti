import { head } from 'ramda';
import uuid from 'uuid/v4';
import { delEditContext, pubsub, setEditContext } from '../database/redis';
import {
  createRelation,
  deleteByID,
  editInputTx,
  loadByID,
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
    $killChainPhase has kill_chain_name "${killChainPhase.name}";
    $killChainPhase has phase_name "${killChainPhase.description}";
    $killChainPhase has created ${now()};
    $killChainPhase has modified ${now()};
    $killChainPhase has revoked false;
    $killChainPhase has created_at ${now()};
    $killChainPhase has updated_at ${now()};
  `);
  return createKillChainPhase.then(result => {
    const { data } = result;
    return findById(head(data).killChainPhase.id).then(
      killChainPhaseCreated => {
        pubsub.publish(BUS_TOPICS.KillChainPhase.ADDED_TOPIC, {
          killChainPhaseCreated
        });
        return killChainPhaseCreated;
      }
    );
  });
};

export const killChainPhaseDelete = killChainPhaseId =>
  deleteByID(killChainPhaseId);

export const killChainPhaseDeleteRelation = relationId =>
  deleteByID(relationId);

export const killChainPhaseAddRelation = (killChainPhaseId, input) =>
  createRelation(killChainPhaseId, input, BUS_TOPICS.KillChainPhase.EDIT_TOPIC);

export const killChainPhaseCleanContext = (user, killChainPhaseId) => {
  delEditContext(user, killChainPhaseId);
  return findById(killChainPhaseId).then(killChainPhase => {
    pubsub.publish(BUS_TOPICS.KillChainPhase.EDIT_TOPIC, {
      instance: killChainPhase
    });
    return killChainPhase;
  });
};

export const killChainPhaseEditContext = (user, killChainPhaseId, input) => {
  setEditContext(user, killChainPhaseId, input);
  findById(killChainPhaseId).then(killChainPhase => {
    pubsub.publish(BUS_TOPICS.KillChainPhase.EDIT_TOPIC, {
      instance: killChainPhase
    });
    return killChainPhase;
  });
};

export const killChainPhaseEditField = (killChainPhaseId, input) =>
  editInputTx(killChainPhaseId, input).then(killChainPhase => {
    pubsub.publish(BUS_TOPICS.KillChainPhase.EDIT_TOPIC, {
      instance: killChainPhase
    });
    return killChainPhase;
  });
