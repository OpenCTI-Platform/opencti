import uuid from 'uuid/v4';
import { delEditContext, setEditContext } from '../database/redis';
import {
  escape,
  escapeString,
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
  commitWriteTx
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';

export const findAll = args =>
  paginate(
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

export const findByEntity = args =>
  paginate(
    `match $k isa Kill-Chain-Phase; 
    $rel(kill_chain_phase:$k, phase_belonging:$so) isa kill_chain_phases; 
    $so has internal_id_key "${escapeString(args.objectId)}"`,
    args
  );

export const findById = killChainPhaseId => getById(killChainPhaseId);

export const findByPhaseName = args =>
  paginate(
    `match $k isa Kill-Chain-Phase; 
    $k has phase_name "${escapeString(args.phaseName)}"`,
    args,
    false
  );

export const markingDefinitions = (killChainPhaseId, args) =>
  paginate(
    `match $marking isa Marking-Definition; 
    (marking:$marking, so:$k) isa object_marking_refs; 
    $k has internal_id_key "${escapeString(killChainPhaseId)}"`,
    args,
    false
  );

export const addKillChainPhase = async (user, killChainPhase) => {
  const wTx = await takeWriteTx();
  const internalId = killChainPhase.internal_id_key
    ? escapeString(killChainPhase.internal_id_key)
    : uuid();
  const killChainPhaseIterator = await wTx.tx
    .query(`insert $killChainPhase isa Kill-Chain-Phase,
    has internal_id_key "${internalId}",
    has entity_type "kill-chain-phase",
    has stix_id_key "${
      killChainPhase.stix_id_key
        ? escapeString(killChainPhase.stix_id_key)
        : `kill-chain-phase--${uuid()}`
    }",
    has kill_chain_name "${escapeString(killChainPhase.kill_chain_name)}",
    has phase_name "${escapeString(killChainPhase.phase_name)}",
    has phase_order ${escape(killChainPhase.phase_order)},
    has created ${
      killChainPhase.created ? prepareDate(killChainPhase.created) : now()
    },
    has modified ${
      killChainPhase.modified ? prepareDate(killChainPhase.modified) : now()
    },
    has revoked false,
    has created_at ${now()},
    has created_at_day "${dayFormat(now())}",
    has created_at_month "${monthFormat(now())}",
    has created_at_year "${yearFormat(now())}",       
    has updated_at ${now()};
  `);
  const createKillChainPhase = await killChainPhaseIterator.next();
  const createdKillChainPhaseId = await createKillChainPhase
    .map()
    .get('killChainPhase').id;

  if (killChainPhase.createdByRef) {
    await wTx.tx.query(
      `match $from id ${createdKillChainPhaseId};
      $to has internal_id_key "${escapeString(killChainPhase.createdByRef)}";
      insert (so: $from, creator: $to)
      isa created_by_ref, has internal_id_key "${uuid()}";`
    );
  }

  await commitWriteTx(wTx);

  return getById(internalId).then(created =>
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
