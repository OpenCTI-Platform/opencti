import { assoc, map } from 'ramda';
import uuid from 'uuid/v4';
import {
  takeWriteTx,
  getById,
  dayFormat,
  monthFormat,
  yearFormat,
  prepareDate,
  notify,
  now,
  prepareString
} from '../database/grakn';
import { index, paginate as elPaginate } from '../database/elasticSearch';
import { BUS_TOPICS, logger } from '../config/conf';

export const findAll = args =>
  elPaginate('stix-domain-entities', assoc('type', 'intrusion-set', args));
// paginate('match $i isa Intrusion-Set', args);

export const search = args =>
  elPaginate('stix-domain-entities', assoc('type', 'intrusion-set', args));
/*
  paginate(
    `match $i isa Intrusion-Set; 
    $i has name $name; 
    $i has alias $alias; 
    { $name contains "${prepareString(args.search)}"; } or
    { $alias contains "${prepareString(args.search)}"; }`,
    args,
    false
  );
*/

export const findById = intrusionSetId => getById(intrusionSetId);

export const addIntrusionSet = async (user, intrusionSet) => {
  const wTx = await takeWriteTx();
  const query = `insert $intrusionSet isa Intrusion-Set,
    has entity_type "intrusion-set",
    has stix_id "${
      intrusionSet.stix_id
        ? prepareString(intrusionSet.stix_id)
        : `intrusion-set--${uuid()}`
    }",
    has stix_label "",
    has alias "",
    has name "${prepareString(intrusionSet.name)}",
    has description "${prepareString(intrusionSet.description)}",
    has first_seen ${
      intrusionSet.first_seen ? prepareDate(intrusionSet.first_seen) : now()
    },
    has first_seen_day "${
      intrusionSet.first_seen
        ? dayFormat(intrusionSet.first_seen)
        : dayFormat(now())
    }",
    has first_seen_month "${
      intrusionSet.first_seen
        ? monthFormat(intrusionSet.first_seen)
        : monthFormat(now())
    }",
    has first_seen_year "${
      intrusionSet.first_seen
        ? yearFormat(intrusionSet.first_seen)
        : yearFormat(now())
    }",
    has last_seen ${
      intrusionSet.last_seen ? prepareDate(intrusionSet.last_seen) : now()
    },
    has last_seen_day "${
      intrusionSet.last_seen
        ? dayFormat(intrusionSet.last_seen)
        : dayFormat(now())
    }",
    has last_seen_month "${
      intrusionSet.last_seen
        ? monthFormat(intrusionSet.last_seen)
        : monthFormat(now())
    }",
    has last_seen_year "${
      intrusionSet.last_seen
        ? yearFormat(intrusionSet.last_seen)
        : yearFormat(now())
    }",
    has goal "${prepareString(intrusionSet.goal)}",
    has sophistication "${prepareString(intrusionSet.sophistication)}",
    has resource_level "${prepareString(intrusionSet.resource_level)}",
    has primary_motivation "${prepareString(intrusionSet.primary_motivation)}",
    has secondary_motivation "${prepareString(
      intrusionSet.secondary_motivation
    )}",
    has created ${
      intrusionSet.created ? prepareDate(intrusionSet.created) : now()
    },
    has modified ${
      intrusionSet.modified ? prepareDate(intrusionSet.modified) : now()
    },
    has revoked false,
    has created_at ${now()},
    has created_at_day "${dayFormat(now())}",
    has created_at_month "${monthFormat(now())}",
    has created_at_year "${yearFormat(now())}",       
    has updated_at ${now()};
  `;
  logger.debug(`[GRAKN - infer: false] ${query}`);
  const intrusionSetIterator = await wTx.query(query);
  const createIntrusionSet = await intrusionSetIterator.next();
  const createdIntrusionSetId = await createIntrusionSet
    .map()
    .get('intrusionSet').id;

  if (intrusionSet.createdByRef) {
    await wTx.query(
      `match $from id ${createdIntrusionSetId};
      $to id ${intrusionSet.createdByRef};
      insert (so: $from, creator: $to)
      isa created_by_ref;`
    );
  }

  if (intrusionSet.markingDefinitions) {
    const createMarkingDefinition = markingDefinition =>
      wTx.query(
        `match $from id ${createdIntrusionSetId}; 
        $to id ${markingDefinition}; 
        insert (so: $from, marking: $to) isa object_marking_refs;`
      );
    const markingDefinitionsPromises = map(
      createMarkingDefinition,
      intrusionSet.markingDefinitions
    );
    await Promise.all(markingDefinitionsPromises);
  }

  await wTx.commit();

  return getById(createdIntrusionSetId).then(created => {
    index('stix-domain-entities', 'stix_domain_entity', created);
    return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
  });
};
