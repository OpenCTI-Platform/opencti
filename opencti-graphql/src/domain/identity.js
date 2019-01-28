import { map } from 'ramda';
import uuid from 'uuid/v4';
import {
  deleteByID,
  loadByID,
  notify,
  now,
  paginate,
  takeTx
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';

export const findAll = args => paginate('match $m isa Identity', args);

export const findById = identityId => loadByID(identityId);

export const search = args =>
  paginate(
    `match $m isa Identity
    has name_lowercase $name
    has description_lowercase $desc;
    { $name contains "${args.search.toLowerCase()}"; } or
    { $desc contains "${args.search.toLowerCase()}"; }`,
    args
  );

export const addIdentity = async (user, identity) => {
  const wTx = await takeTx();
  const identityIterator = await wTx.query(`insert $identity isa ${
    identity.type
  } 
    has type "${identity.type.toLowerCase()}";
    $identity has stix_id "${identity.type.toLowerCase()}--${uuid()}";
    $identity has stix_label "";
    $identity has stix_label_lowercase "";
    $identity has alias "";
    $identity has alias_lowercase "";
    $identity has name "${identity.name}";
    $identity has description "${identity.description}";
    $identity has name_lowercase "${identity.name.toLowerCase()}";
    $identity has description_lowercase "${
      identity.description ? identity.description.toLowerCase() : ''
    }";
    $identity has created ${now()};
    $identity has modified ${now()};
    $identity has revoked false;
    $identity has created_at ${now()};
    $identity has updated_at ${now()};
  `);
  const createIdentity = await identityIterator.next();
  const createdIdentityId = await createIdentity.map().get('identity').id;

  if (identity.createdByRef) {
    await wTx.query(`match $from id ${createdIdentityId};
         $to id ${identity.createdByRef};
         insert (so: $from, creator: $to)
         isa created_by_ref;`);
  }

  if (identity.markingDefinitions) {
    const createMarkingDefinition = markingDefinition =>
      wTx.query(
        `match $from id ${createdIdentityId}; $to id ${markingDefinition}; insert (so: $from, marking: $to) isa object_marking_refs;`
      );
    const markingDefinitionsPromises = map(
      createMarkingDefinition,
      identity.markingDefinitions
    );
    await Promise.all(markingDefinitionsPromises);
  }

  await wTx.commit();

  return loadByID(createdIdentityId).then(created =>
    notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user)
  );
};

export const identityDelete = identityId => deleteByID(identityId);
