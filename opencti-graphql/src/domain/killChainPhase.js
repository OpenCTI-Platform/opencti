import { assoc, head } from 'ramda';
import {
  pubsub,
  setEditContext,
  fetchEditContext,
  delEditContext
} from '../database/redis';
import {
  deleteByID,
  loadByID,
  qk,
  now,
  editInput,
  paginate,
  createRelation
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
    has type "KillChainPhase";
    $killChainPhase has kill_chain_name "${killChainPhase.kill_chain_name}";
    $killChainPhase has phase_name "${killChainPhase.phase_name}";
    $killChainPhase has order "${killChainPhase.order}";
    $killChainPhase has created ${now()};
    $killChainPhase has modified ${now()};
    $killChainPhase has revoked false;
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

export const killChainPhaseCleanContext = (user, killChainPhaseId) =>
  delEditContext(user, killChainPhaseId);

export const killChainPhaseEditContext = (user, killChainPhaseId, input) => {
  setEditContext(user, killChainPhaseId, input);
  const killChainPhasePromise = findById(killChainPhaseId);
  const contextPromise = fetchEditContext(killChainPhaseId);
  return Promise.all([killChainPhasePromise, contextPromise]).then(
    ([killChainPhase, context]) => {
      pubsub.publish(BUS_TOPICS.KillChainPhase.EDIT_TOPIC, {
        instance: killChainPhase,
        context
      });
      return killChainPhase;
    }
  );
};

export const killChainPhaseEditField = (killChainPhaseId, input) => {
  const contextPromise = fetchEditContext(killChainPhaseId);
  const inputPromise = editInput(assoc('id', killChainPhaseId, input));
  return Promise.all([contextPromise, inputPromise]).then(
    ([context, killChainPhase]) => {
      pubsub.publish(BUS_TOPICS.KillChainPhase.EDIT_TOPIC, {
        instance: killChainPhase,
        context
      });
      return killChainPhase;
    }
  );
};
