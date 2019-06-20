import { assoc, map } from 'ramda';
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
  paginate,
  takeWriteTx,
  commitWriteTx
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { index, paginate as elPaginate } from '../database/elasticSearch';

export const findAll = args =>
  elPaginate('stix-domain-entities', assoc('type', 'sector', args));
// paginate('match $s isa Sector', args);

export const findById = sectorId => getById(sectorId);

export const markingDefinitions = (sectorId, args) =>
  paginate(
    `match $marking isa Marking-Definition; 
    $rel(marking:$marking, so:$s) isa object_marking_refs; 
    $s has internal_id "${escapeString(sectorId)}"`,
    args
  );

export const subsectors = (sectorId, args) =>
  paginate(
    `match $subsector isa Sector; 
    $rel(gather:$s, part_of:$subsector) isa gathering; 
    $s has internal_id "${escapeString(sectorId)}"`,
    args
  );

export const addSector = async (user, sector) => {
  const wTx = await takeWriteTx();
  const internalId = sector.internal_id
    ? escapeString(sector.internal_id)
    : uuid();
  const sectorIterator = await wTx.tx.query(`insert $sector isa Sector,
    has internal_id "${internalId}",
    has entity_type "sector",
    has stix_id "${
      sector.stix_id ? escapeString(sector.stix_id) : `sector--${uuid()}`
    }",
    has stix_label "",
    has alias "",
    has name "${escapeString(sector.name)}",
    has description "${escapeString(sector.description)}",
    has created ${sector.created ? prepareDate(sector.created) : now()},
    has modified ${sector.modified ? prepareDate(sector.modified) : now()},
    has revoked false,
    has created_at ${now()},
    has created_at_day "${dayFormat(now())}",
    has created_at_month "${monthFormat(now())}",
    has created_at_year "${yearFormat(now())}",       
    has updated_at ${now()};
  `);
  const createSector = await sectorIterator.next();
  const createdSectorId = await createSector.map().get('sector').id;

  if (sector.createdByRef) {
    await wTx.tx.query(
      `match $from id ${createdSectorId};
      $to has internal_id "${escapeString(sector.createdByRef)}";
      insert (so: $from, creator: $to)
      isa created_by_ref, has internal_id "${uuid()}";`
    );
  }

  if (sector.markingDefinitions) {
    const createMarkingDefinition = markingDefinition =>
      wTx.tx.query(
        `match $from id ${createdSectorId}; 
        $to has internal_id "${escapeString(markingDefinition)}";
        insert (so: $from, marking: $to) isa object_marking_refs, has internal_id "${uuid()}";`
      );
    const markingDefinitionsPromises = map(
      createMarkingDefinition,
      sector.markingDefinitions
    );
    await Promise.all(markingDefinitionsPromises);
  }

  await commitWriteTx(wTx);

  return getById(internalId).then(created => {
    index('stix-domain-entities', 'stix_domain_entity', created);
    return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
  });
};
