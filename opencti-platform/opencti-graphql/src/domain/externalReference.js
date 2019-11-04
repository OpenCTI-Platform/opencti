import uuid from 'uuid/v4';
import { delEditContext, setEditContext } from '../database/redis';
import {
  createRelation,
  dayFormat,
  deleteEntityById,
  deleteRelationById,
  escapeString,
  executeWrite,
  refetchEntityById,
  getGraknId,
  graknNow,
  monthFormat,
  notify,
  paginate,
  prepareDate,
  updateAttribute,
  yearFormat
} from '../database/grakn';
import { BUS_TOPICS, logger } from '../config/conf';
import {
  deleteEntity, loadById,
  paginate as elPaginate
} from '../database/elasticSearch';
import { linkCreatedByRef, linkMarkingDef } from './stixEntity';

export const findAll = args => elPaginate('external_references', args);

export const findByEntity = args => {
  return paginate(
    `match $e isa External-Reference; 
    $rel(external_reference:$e, so:$so) isa external_references;
    $so has internal_id_key "${escapeString(args.objectId)}"`,
    args
  );
};

export const findById = externalReferenceId =>
  refetchEntityById(externalReferenceId);

export const addExternalReference = async (user, externalReference) => {
  const externalId = await executeWrite(async wTx => {
    const internalId = externalReference.internal_id_key
      ? escapeString(externalReference.internal_id_key)
      : uuid();
    const now = graknNow();
    const query = `insert $externalReference isa External-Reference,
    has internal_id_key "${internalId}",
    has entity_type "external-reference",
    has stix_id_key "${
      externalReference.stix_id_key
        ? escapeString(externalReference.stix_id_key)
        : `external-reference--${uuid()}`
    }",
    has source_name "${escapeString(externalReference.source_name)}",
    has description "${escapeString(externalReference.description)}",
    has url "${
      externalReference.url ? escapeString(externalReference.url) : ''
    }",
    has hash "${escapeString(externalReference.hash)}",
    has external_id "${escapeString(externalReference.external_id)}",
    has created ${
      externalReference.created ? prepareDate(externalReference.created) : now
    },
    has modified ${
      externalReference.modified ? prepareDate(externalReference.modified) : now
    },
    has revoked false,
    has created_at ${now},
    has created_at_day "${dayFormat(now)}",
    has created_at_month "${monthFormat(now)}",
    has created_at_year "${yearFormat(now)}",  
    has updated_at ${now};
  `;
    logger.debug(`[GRAKN - infer: false] addExternalReference > ${query}`);
    const externalReferenceIterator = await wTx.tx.query(query);
    const createExternalRef = await externalReferenceIterator.next();
    const createdId = await createExternalRef.map().get('externalReference').id;

    // Create associated relations
    await linkCreatedByRef(wTx, createdId, externalReference.createdByRef);
    await linkMarkingDef(wTx, createdId, externalReference.markingDefinitions);
    return internalId;
  });
  return refetchEntityById(externalId).then(created => {
    return notify(BUS_TOPICS.ExternalReference.ADDED_TOPIC, created, user);
  });
};

export const externalReferenceDelete = async externalReferenceId => {
  const graknId = await getGraknId(externalReferenceId);
  await deleteEntity('external_references', graknId);
  return deleteEntityById(externalReferenceId);
};

export const externalReferenceAddRelation = (
  user,
  externalReferenceId,
  input
) =>
  createRelation(externalReferenceId, input).then(relationData => {
    notify(BUS_TOPICS.ExternalReference.EDIT_TOPIC, relationData.node, user);
    return relationData;
  });

export const externalReferenceDeleteRelation = (
  user,
  externalReferenceId,
  relationId
) =>
  deleteRelationById(externalReferenceId, relationId).then(relationData => {
    notify(BUS_TOPICS.ExternalReference.EDIT_TOPIC, relationData.node, user);
    return relationData;
  });

export const externalReferenceCleanContext = (user, externalReferenceId) => {
  delEditContext(user, externalReferenceId);
  return refetchEntityById(externalReferenceId).then(externalReference =>
    notify(BUS_TOPICS.ExternalReference.EDIT_TOPIC, externalReference, user)
  );
};

export const externalReferenceEditContext = (
  user,
  externalReferenceId,
  input
) => {
  setEditContext(user, externalReferenceId, input);
  return refetchEntityById(externalReferenceId).then(externalReference =>
    notify(BUS_TOPICS.ExternalReference.EDIT_TOPIC, externalReference, user)
  );
};

export const externalReferenceEditField = (
  user,
  externalReferenceId,
  input
) => {
  return executeWrite(wTx => {
    return updateAttribute(externalReferenceId, input, wTx);
  }).then(async () => {
    const externalReference = await loadById(externalReferenceId);
    return notify(
      BUS_TOPICS.ExternalReference.EDIT_TOPIC,
      externalReference,
      user
    );
  });
};
