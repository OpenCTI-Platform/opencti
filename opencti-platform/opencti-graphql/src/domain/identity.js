import { map, assoc } from 'ramda';
import uuid from 'uuid/v4';
import {
  escapeString,
  getById,
  prepareDate,
  dayFormat,
  monthFormat,
  yearFormat,
  notify,
  now,
  takeWriteTx,
  commitWriteTx
} from '../database/grakn';
import { BUS_TOPICS, logger } from '../config/conf';
import { paginate as elPaginate } from '../database/elasticSearch';

export const findAll = args =>
  elPaginate(
    'stix_domain_entities',
    assoc('types', ['user', 'organization', 'region', 'country', 'city'], args)
  );

export const findById = identityId => getById(identityId);

export const addIdentity = async (user, identity) => {
  const wTx = await takeWriteTx();
  const internalId = identity.internal_id
    ? escapeString(identity.internal_id)
    : uuid();
  const query = `insert $identity isa ${identity.type},
    has internal_id "${internalId}",
    has entity_type "${identity.type.toLowerCase()}",
    has stix_id "${
      identity.stix_id
        ? escapeString(identity.stix_id)
        : `${escapeString(identity.type.toLowerCase())}--${uuid()}`
    }",
    has stix_label "",
    has alias "",
    has name "${escapeString(identity.name)}",
    has description "${escapeString(identity.description)}",
    has created ${identity.created ? prepareDate(identity.created) : now()},
    has modified ${identity.modified ? prepareDate(identity.modified) : now()},
    has revoked false,
    has created_at ${now()},
    has created_at_day "${dayFormat(now())}",
    has created_at_month "${monthFormat(now())}",
    has created_at_year "${yearFormat(now())}", 
    has updated_at ${now()};
  `;
  const identityIterator = await wTx.tx.query(query);
  logger.debug(`[GRAKN - infer: false] addIdentity > ${query}`);
  const createIdentity = await identityIterator.next();
  const createdIdentityId = await createIdentity.map().get('identity').id;

  if (identity.createdByRef) {
    await wTx.tx.query(
      `match $from id ${createdIdentityId};
      $to has internal_id "${escapeString(identity.createdByRef)}";
      insert (so: $from, creator: $to)
      isa created_by_ref, has internal_id "${uuid()}";`
    );
  }

  if (identity.markingDefinitions) {
    const createMarkingDefinition = markingDefinition =>
      wTx.tx.query(
        `match $from id ${createdIdentityId}; 
        $to has internal_id "${escapeString(markingDefinition)}"; 
        insert (so: $from, marking: $to) isa object_marking_refs, has internal_id "${uuid()}";`
      );
    const markingDefinitionsPromises = map(
      createMarkingDefinition,
      identity.markingDefinitions
    );
    await Promise.all(markingDefinitionsPromises);
  }

  await commitWriteTx(wTx);

  return getById(internalId).then(created => {
    return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
  });
};
