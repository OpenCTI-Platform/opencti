import { map } from 'ramda';
import uuid from 'uuid/v4';
import {
  deleteByID,
  loadByID,
  dayFormat,
  monthFormat,
  yearFormat,
  notify,
  now,
  paginate,
  takeTx,
  prepareString
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';

export const findAll = args => paginate('match $m isa Identity', args, false);

export const findById = identityId => loadByID(identityId);

export const search = args =>
  paginate(
    `match $m isa Identity
    has name_lowercase $name;
    $m has alias_lowercase $alias;
    { $name contains "${prepareString(args.search.toLowerCase())}"; } or
    { $alias contains "${prepareString(args.search.toLowerCase())}"; }`,
    args,
    false
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
    $identity has name "${prepareString(identity.name)}";
    $identity has description "${prepareString(identity.description)}";
    $identity has name_lowercase "${prepareString(
      identity.name.toLowerCase()
    )}";
    $identity has description_lowercase "${
      identity.description
        ? prepareString(identity.description.toLowerCase())
        : ''
    }";
    $identity has created ${now()};
    $identity has modified ${now()};
    $identity has revoked false;
    $identity has created_at ${now()};
    $identity has created_at_day "${dayFormat(now())}";
    $identity has created_at_month "${monthFormat(now())}";
    $identity has created_at_year "${yearFormat(now())}";   
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
