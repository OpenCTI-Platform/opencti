import { assoc, join, tail, head, map } from 'ramda';
import uuid from 'uuid/v4';
import {
  commitWriteTx,
  dayFormat,
  escapeString,
  getById,
  graknNow,
  monthFormat,
  notify,
  prepareDate,
  takeWriteTx,
  yearFormat
} from '../database/grakn';
import { paginate as elPaginate } from '../database/elasticSearch';
import { BUS_TOPICS, logger } from '../config/conf';
import { linkCreatedByRef, linkMarkingDef } from './stixEntity';

export const findAll = args => {
  return elPaginate(
    'stix_domain_entities',
    assoc('type', 'intrusion-set', args)
  );
};

export const findById = intrusionSetId => getById(intrusionSetId);

export const addIntrusionSet = async (user, intrusionSet) => {
  const wTx = await takeWriteTx();
  const internalId = intrusionSet.internal_id_key
    ? escapeString(intrusionSet.internal_id_key)
    : uuid();
  const now = graknNow();
  const query = `insert $intrusionSet isa Intrusion-Set,
    has internal_id_key "${internalId}",
    has entity_type "intrusion-set",
    has stix_id_key "${
      intrusionSet.stix_id_key
        ? escapeString(intrusionSet.stix_id_key)
        : `intrusion-set--${uuid()}`
    }",
    has stix_label "",
    ${
      intrusionSet.alias
        ? `${join(
            ' ',
            map(
              val => `has alias "${escapeString(val)}",`,
              tail(intrusionSet.alias)
            )
          )} has alias "${escapeString(head(intrusionSet.alias))}",`
        : 'has alias "",'
    }
    has name "${escapeString(intrusionSet.name)}",
    has description "${escapeString(intrusionSet.description)}",
    has first_seen ${
      intrusionSet.first_seen ? prepareDate(intrusionSet.first_seen) : now
    },
    has first_seen_day "${
      intrusionSet.first_seen
        ? dayFormat(intrusionSet.first_seen)
        : dayFormat(now)
    }",
    has first_seen_month "${
      intrusionSet.first_seen
        ? monthFormat(intrusionSet.first_seen)
        : monthFormat(now)
    }",
    has first_seen_year "${
      intrusionSet.first_seen
        ? yearFormat(intrusionSet.first_seen)
        : yearFormat(now)
    }",
    has last_seen ${
      intrusionSet.last_seen ? prepareDate(intrusionSet.last_seen) : now
    },
    has last_seen_day "${
      intrusionSet.last_seen
        ? dayFormat(intrusionSet.last_seen)
        : dayFormat(now)
    }",
    has last_seen_month "${
      intrusionSet.last_seen
        ? monthFormat(intrusionSet.last_seen)
        : monthFormat(now)
    }",
    has last_seen_year "${
      intrusionSet.last_seen
        ? yearFormat(intrusionSet.last_seen)
        : yearFormat(now)
    }",
    has goal "${escapeString(intrusionSet.goal)}",
    has sophistication "${escapeString(intrusionSet.sophistication)}",
    has resource_level "${escapeString(intrusionSet.resource_level)}",
    has primary_motivation "${escapeString(intrusionSet.primary_motivation)}",
    has secondary_motivation "${escapeString(
      intrusionSet.secondary_motivation
    )}",
    has created ${
      intrusionSet.created ? prepareDate(intrusionSet.created) : now
    },
    has modified ${
      intrusionSet.modified ? prepareDate(intrusionSet.modified) : now
    },
    has revoked false,
    has created_at ${now},
    has created_at_day "${dayFormat(now)}",
    has created_at_month "${monthFormat(now)}",
    has created_at_year "${yearFormat(now)}",       
    has updated_at ${now};
  `;
  logger.debug(`[GRAKN - infer: false] addIntrusionSet > ${query}`);
  const intrusionSetIterator = await wTx.tx.query(query);
  const createIntrusionSet = await intrusionSetIterator.next();
  const createdId = await createIntrusionSet.map().get('intrusionSet').id;

  // Create associated relations
  await linkCreatedByRef(wTx, createdId, intrusionSet.createdByRef);
  await linkMarkingDef(wTx, createdId, intrusionSet.markingDefinitions);

  // Commit everything and return the data
  await commitWriteTx(wTx);
  return getById(internalId).then(created => {
    return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
  });
};
