import { map } from 'ramda';
import uuid from 'uuid/v4';
import { delEditContext, setEditContext } from '../database/redis';
import {
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
  getId,
  commitWriteTx
} from '../database/grakn';
import { BUS_TOPICS, logger } from '../config/conf';
import {
  deleteEntity,
  index,
  paginate as elPaginate
} from '../database/elasticSearch';

export const findAll = args => elPaginate('external_references', args);
//  paginate('match $e isa External-Reference', args);

export const findByEntity = args =>
  paginate(
    `match $e isa External-Reference; 
    $rel(external_reference:$e, so:$so) isa external_references;
    $so has internal_id "${escapeString(args.objectId)}"`,
    args
  );

export const findById = externalReferenceId => getById(externalReferenceId);

export const search = args => elPaginate('external_references', args);
/*  paginate(
    `match $e isa External-Reference; 
    $e has source_name $sn; 
    $e has description $desc; 
    $e has url $url; 
    { $sn contains "${escapeString(args.search)}"; } or
    { $desc contains "${escapeString(args.search)}"; } or
    { $url contains "${escapeString(args.search)}"; }`,
    args,
    false
  );
*/

export const addExternalReference = async (user, externalReference) => {
  const wTx = await takeWriteTx();
  const internalId = externalReference.internal_id
    ? escapeString(externalReference.internal_id)
    : uuid();
  const query = `insert $externalReference isa External-Reference,
    has internal_id "${internalId}",
    has entity_type "external-reference",
    has stix_id "${
      externalReference.stix_id
        ? escapeString(externalReference.stix_id)
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
      externalReference.created ? prepareDate(externalReference.created) : now()
    },
    has modified ${
      externalReference.modified
        ? prepareDate(externalReference.modified)
        : now()
    },
    has revoked false,
    has created_at ${now()},
    has created_at_day "${dayFormat(now())}",
    has created_at_month "${monthFormat(now())}",
    has created_at_year "${yearFormat(now())}",  
    has updated_at ${now()};
  `;
  logger.debug(`[GRAKN - infer: false] ${query}`);
  const externalReferenceIterator = await wTx.tx.query(query);
  const createExternalReference = await externalReferenceIterator.next();
  const createdExternalReferenceId = await createExternalReference
    .map()
    .get('externalReference').id;

  if (externalReference.createdByRef) {
    await wTx.tx.query(
      `match $from id ${createdExternalReferenceId};
      $to has internal_id "${escapeString(externalReference.createdByRef)}";
      insert (so: $from, creator: $to)
      isa created_by_ref, has internal_id "${uuid()}";`
    );
  }

  if (externalReference.markingDefinitions) {
    const createMarkingDefinition = markingDefinition =>
      wTx.tx.query(
        `match $from id ${createdExternalReferenceId}; 
        $to has internal_id "${escapeString(markingDefinition)}"; 
        insert (so: $from, marking: $to) isa object_marking_refs, has internal_id "${uuid()}";`
      );
    const markingDefinitionsPromises = map(
      createMarkingDefinition,
      externalReference.markingDefinitions
    );
    await Promise.all(markingDefinitionsPromises);
  }

  await commitWriteTx(wTx);

  return getById(internalId).then(created => {
    index('external_references', created);
    return notify(BUS_TOPICS.ExternalReference.ADDED_TOPIC, created, user);
  });
};

export const externalReferenceDelete = async externalReferenceId => {
  const graknId = await getId(externalReferenceId);
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
  return getById(externalReferenceId).then(externalReference =>
    notify(BUS_TOPICS.ExternalReference.EDIT_TOPIC, externalReference, user)
  );
};

export const externalReferenceEditContext = (
  user,
  externalReferenceId,
  input
) => {
  setEditContext(user, externalReferenceId, input);
  return getById(externalReferenceId).then(externalReference =>
    notify(BUS_TOPICS.ExternalReference.EDIT_TOPIC, externalReference, user)
  );
};

export const externalReferenceEditField = (user, externalReferenceId, input) =>
  updateAttribute(externalReferenceId, input).then(externalReference => {
    index('external_references', externalReference);
    return notify(
      BUS_TOPICS.ExternalReference.EDIT_TOPIC,
      externalReference,
      user
    );
  });
