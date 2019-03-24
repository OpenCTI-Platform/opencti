import uuid from 'uuid/v4';
import { delEditContext, setEditContext } from '../database/redis';
import {
  createRelation,
  deleteEntityById,
  deleteRelationById,
  updateAttribute,
  getById,
  prepareDate,
  dayFormat,
  monthFormat,
  yearFormat,
  notify,
  now,
  paginate,
  takeWriteTx,
  prepareString
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';

export const findAll = args => paginate('match $k isa Kill-Chain-Phase', args);
export const findByEntity = args =>
  paginate(
    `match $killChainPhase isa Kill-Chain-Phase; 
    $rel(kill_chain_phase:$killChainPhase, phase_belonging:$so) isa kill_chain_phases; 
    $so id ${args.objectId}`,
    args
  );

export const findById = killChainPhaseId => getById(killChainPhaseId);

export const findByPhaseName = args =>
  paginate(
    `match $m isa Kill-Chain-Phase; $m has phase_name "${prepareString(
      args.phaseName
    )}"`,
    args,
    false
  );

export const markingDefinitions = (killChainPhaseId, args) =>
  paginate(
    `match $marking isa Marking-Definition; 
    (marking:$marking, so:$killChainPhase) isa object_marking_refs; 
    $killChainPhase id ${killChainPhaseId}`,
    args,
    false
  );

export const addKillChainPhase = async (user, killChainPhase) => {
  const wTx = await takeWriteTx();
  const killChainPhaseIterator = await wTx.query(`insert $killChainPhase isa Kill-Chain-Phase
    has type "kill-chain-phase";
    $killChainPhase has stix_id "${
      killChainPhase.stix_id
        ? prepareString(killChainPhase.stix_id)
        : `kill-chain-phase--${uuid()}`
    }";
    $killChainPhase has kill_chain_name "${prepareString(
      killChainPhase.kill_chain_name
    )}";
    $killChainPhase has phase_name "${prepareString(
      killChainPhase.phase_name
    )}";
    $killChainPhase has phase_order ${killChainPhase.phase_order};
    $killChainPhase has created ${
      killChainPhase.created ? prepareDate(killChainPhase.created) : now()
    };
    $killChainPhase has modified ${
      killChainPhase.modified ? prepareDate(killChainPhase.modified) : now()
    };
    $killChainPhase has revoked false;
    $killChainPhase has created_at ${now()};
    $killChainPhase has created_at_day "${dayFormat(now())}";
    $killChainPhase has created_at_month "${monthFormat(now())}";
    $killChainPhase has created_at_year "${yearFormat(now())}";       
    $killChainPhase has updated_at ${now()};
  `);
  const createKillChainPhase = await killChainPhaseIterator.next();
  const createdKillChainPhaseId = await createKillChainPhase
    .map()
    .get('killChainPhase').id;

  if (killChainPhase.createdByRef) {
    await wTx.query(`match $from id ${createdKillChainPhaseId};
         $to id ${killChainPhase.createdByRef};
         insert (so: $from, creator: $to)
         isa created_by_ref;`);
  }

  await wTx.commit();

  return getById(createdKillChainPhaseId).then(created =>
    notify(BUS_TOPICS.KillChainPhase.ADDED_TOPIC, created, user)
  );
};

export const killChainPhaseDelete = killChainPhaseId =>
  deleteEntityById(killChainPhaseId);

export const killChainPhaseAddRelation = (user, killChainPhaseId, input) =>
  createRelation(killChainPhaseId, input).then(relationData => {
    notify(BUS_TOPICS.KillChainPhase.EDIT_TOPIC, relationData.node, user);
    return relationData;
  });

export const killChainPhaseDeleteRelation = (
  user,
  killChainPhaseId,
  relationId
) =>
  deleteRelationById(killChainPhaseId, relationId).then(relationData => {
    notify(BUS_TOPICS.KillChainPhase.EDIT_TOPIC, relationData.node, user);
    return relationData;
  });

export const killChainPhaseCleanContext = (user, killChainPhaseId) => {
  delEditContext(user, killChainPhaseId);
  return getById(killChainPhaseId).then(killChainPhase =>
    notify(BUS_TOPICS.KillChainPhase.EDIT_TOPIC, killChainPhase, user)
  );
};

export const killChainPhaseEditContext = (user, killChainPhaseId, input) => {
  setEditContext(user, killChainPhaseId, input);
  return getById(killChainPhaseId).then(killChainPhase =>
    notify(BUS_TOPICS.KillChainPhase.EDIT_TOPIC, killChainPhase, user)
  );
};

export const killChainPhaseEditField = (user, killChainPhaseId, input) =>
  updateAttribute(killChainPhaseId, input).then(killChainPhase =>
    notify(BUS_TOPICS.KillChainPhase.EDIT_TOPIC, killChainPhase, user)
  );
