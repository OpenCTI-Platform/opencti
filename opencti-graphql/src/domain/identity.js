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
import { BUS_TOPICS, logger } from '../config/conf';
import { index } from '../database/elasticSearch';

export const findAll = args => paginate('match $i isa Identity', args, false);

export const findById = identityId => getById(identityId);

export const search = args =>
  paginate(
    `match $i isa Identity; 
    $i has name $name; 
    $i has alias $alias; 
    { $name contains "${prepareString(args.search)}"; } or 
    { $alias contains "${prepareString(args.search)}"; }`,
    args,
    false
  );

export const addIdentity = async (user, identity) => {
  const wTx = await takeWriteTx();
  const query = `insert $identity isa ${identity.type},
    has entity_type "${identity.type.toLowerCase()}",
    has stix_id "${
      identity.stix_id
        ? prepareString(identity.stix_id)
        : `${prepareString(identity.type.toLowerCase())}--${uuid()}`
    }",
    has stix_label "",
    has alias "",
    has name "${prepareString(identity.name)}",
    has description "${prepareString(identity.description)}",
    has created ${identity.created ? prepareDate(identity.created) : now()},
    has modified ${identity.modified ? prepareDate(identity.modified) : now()},
    has revoked false,
    has created_at ${now()},
    has created_at_day "${dayFormat(now())}",
    has created_at_month "${monthFormat(now())}",
    has created_at_year "${yearFormat(now())}", 
    has updated_at ${now()};
  `;
  const identityIterator = await wTx.query(query);
  logger.debug(`[GRAKN - infer: false] ${query}`);
  const createIdentity = await identityIterator.next();
  const createdIdentityId = await createIdentity.map().get('identity').id;

  if (identity.createdByRef) {
    await wTx.query(
      `match $from id ${createdIdentityId};
      $to id ${identity.createdByRef};
      insert (so: $from, creator: $to)
      isa created_by_ref;`
    );
  }

  if (identity.markingDefinitions) {
    const createMarkingDefinition = markingDefinition =>
      wTx.query(
        `match $from id ${createdIdentityId}; 
        $to id ${markingDefinition}; 
        insert (so: $from, marking: $to) isa object_marking_refs;`
      );
    const markingDefinitionsPromises = map(
      createMarkingDefinition,
      identity.markingDefinitions
    );
    await Promise.all(markingDefinitionsPromises);
  }

  await wTx.commit();

  return getById(createdIdentityId).then(created => {
    index('stix-domain-entities', 'stix_domain_entity', created);
    return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
  });
};

export const identityDelete = identityId => deleteEntityById(identityId);
