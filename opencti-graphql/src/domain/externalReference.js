import { assoc, map } from 'ramda';
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
  prepareString,
  takeWriteTx
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import {
  deleteEntity,
  index,
  paginate as elPaginate
} from '../database/elasticSearch';

export const findAll = args => elPaginate('external-references', args);
//  paginate('match $e isa External-Reference', args);

export const findByEntity = args =>
  paginate(
    `match $e isa External-Reference; 
    $rel(external_reference:$e, so:$so) isa external_references;
    $so id ${args.objectId}`,
    args
  );

export const findById = externalReferenceId => getById(externalReferenceId);

export const search = args => elPaginate('external-references', args);
/*  paginate(
    `match $e isa External-Reference; 
    $e has source_name $sn; 
    $e has description $desc; 
    $e has url $url; 
    { $sn contains "${prepareString(args.search)}"; } or 
    { $desc contains "${prepareString(args.search)}"; } or 
    { $url contains "${prepareString(args.search)}"; }`,
    args,
    false
  );
*/

export const addExternalReference = async (user, externalReference) => {
  const wTx = await takeWriteTx();
  const externalReferenceIterator = await wTx.query(`insert $externalReference isa External-Reference,
    has entity_type "external-reference",
    has stix_id "${
      externalReference.stix_id
        ? prepareString(externalReference.stix_id)
        : `external-reference--${uuid()}`
    }",
    has source_name "${prepareString(externalReference.source_name)}",
    has description "${prepareString(externalReference.description)}",
    has url "${
      externalReference.url ? prepareString(externalReference.url) : ''
    }",
    has hash "${prepareString(externalReference.hash)}",
    has external_id "${prepareString(externalReference.external_id)}",
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
  `);
  const createExternalReference = await externalReferenceIterator.next();
  const createdExternalReferenceId = await createExternalReference
    .map()
    .get('externalReference').id;

  if (externalReference.createdByRef) {
    await wTx.query(
      `match $from id ${createdExternalReferenceId};
      $to id ${externalReference.createdByRef};
      insert (so: $from, creator: $to)
      isa created_by_ref;`
    );
  }

  if (externalReference.markingDefinitions) {
    const createMarkingDefinition = markingDefinition =>
      wTx.query(
        `match $from id ${createdExternalReferenceId}; 
        $to id ${markingDefinition}; 
        insert (so: $from, marking: $to) isa object_marking_refs;`
      );
    const markingDefinitionsPromises = map(
      createMarkingDefinition,
      externalReference.markingDefinitions
    );
    await Promise.all(markingDefinitionsPromises);
  }

  await wTx.commit();

  return getById(createdExternalReferenceId).then(created => {
    index('external-references', 'external_reference', created);
    return notify(BUS_TOPICS.ExternalReference.ADDED_TOPIC, created, user);
  });
};

export const externalReferenceDelete = externalReferenceId => {
  deleteEntity(
    'external-references',
    'external_reference',
    externalReferenceId
  );
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
    index('external-references', 'external_reference', externalReference);
    return notify(
      BUS_TOPICS.ExternalReference.EDIT_TOPIC,
      externalReference,
      user
    );
  });
