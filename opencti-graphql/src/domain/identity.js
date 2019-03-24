import { map } from 'ramda';
import uuid from 'uuid/v4';
import {
  deleteEntityById,
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

export const findAll = args => paginate('match $m isa Identity', args, false);

export const findById = identityId => getById(identityId);

export const search = args =>
  paginate(
    `match $m isa Identity
    has name $name;
    $m has alias $alias;
    { $name contains "${prepareString(args.search)}"; } or
    { $alias contains "${prepareString(args.search)}"; }`,
    args,
    false
  );

export const addIdentity = async (user, identity) => {
  const wTx = await takeWriteTx();
  const identityIterator = await wTx.query(`insert $identity isa ${
    identity.type
  }
    has type "${identity.type.toLowerCase()}";
    $identity has stix_id "${
      identity.stix_id
        ? prepareString(identity.stix_id)
        : `${prepareString(identity.type.toLowerCase())}--${uuid()}`
    }";
    $identity has stix_label "";
    $identity has alias "";
    $identity has name "${prepareString(identity.name)}";
    $identity has description "${prepareString(identity.description)}";
    $identity has created ${
      identity.created ? prepareDate(identity.created) : now()
    };
    $identity has modified ${
      identity.modified ? prepareDate(identity.modified) : now()
    };
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

  return getById(createdIdentityId).then(created =>
    notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user)
  );
};

export const identityDelete = identityId => deleteEntityById(identityId);
