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
  graknNow,
  paginate,
  takeWriteTx,
  commitWriteTx,
  getSingleValueNumber
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { paginate as elPaginate } from '../database/elasticSearch';

export const findAll = args =>
  elPaginate('stix_domain_entities', assoc('type', 'sector', args));

export const findById = sectorId => getById(sectorId);

export const markingDefinitions = (sectorId, args) =>
  paginate(
    `match $marking isa Marking-Definition; 
    $rel(marking:$marking, so:$s) isa object_marking_refs; 
    $s has internal_id_key "${escapeString(sectorId)}"`,
    args
  );

export const subsectors = (sectorId, args) =>
  paginate(
    `match $subsector isa Sector; 
    $rel(gather:$s, part_of:$subsector) isa gathering; 
    $s has internal_id_key "${escapeString(sectorId)}"`,
    args
  );

export const isSubsector = async (sectorId, args) => {
  const numberOfParents = await getSingleValueNumber(
    `match $parent isa Sector; 
    $rel(gather:$parent, part_of:$subsector) isa gathering; 
    $subsector has internal_id_key "${escapeString(sectorId)}"; get; count;`,
    args
  );
  return numberOfParents > 0;
};

export const addSector = async (user, sector) => {
  const wTx = await takeWriteTx();
  const internalId = sector.internal_id_key
    ? escapeString(sector.internal_id_key)
    : uuid();
  const sectorIterator = await wTx.tx.query(`insert $sector isa Sector,
    has internal_id_key "${internalId}",
    has entity_type "sector",
    has stix_id_key "${
      sector.stix_id_key ? escapeString(sector.stix_id_key) : `identity--${uuid()}`
    }",
    has stix_label "",
    has alias "",
    has name "${escapeString(sector.name)}",
    has description "${escapeString(sector.description)}",
    has created ${sector.created ? prepareDate(sector.created) : graknNow()},
    has modified ${sector.modified ? prepareDate(sector.modified) : graknNow()},
    has revoked false,
    has created_at ${graknNow()},
    has created_at_day "${dayFormat(graknNow())}",
    has created_at_month "${monthFormat(graknNow())}",
    has created_at_year "${yearFormat(graknNow())}",       
    has updated_at ${graknNow()};
  `);
  const createSector = await sectorIterator.next();
  const createdSectorId = await createSector.map().get('sector').id;

  if (sector.createdByRef) {
    await wTx.tx.query(
      `match $from id ${createdSectorId};
      $to has internal_id_key "${escapeString(sector.createdByRef)}";
      insert (so: $from, creator: $to)
      isa created_by_ref, has internal_id_key "${uuid()}";`
    );
  }

  if (sector.markingDefinitions) {
    const createMarkingDefinition = markingDefinition =>
      wTx.tx.query(
        `match $from id ${createdSectorId}; 
        $to has internal_id_key "${escapeString(markingDefinition)}";
        insert (so: $from, marking: $to) isa object_marking_refs, has internal_id_key "${uuid()}";`
      );
    const markingDefinitionsPromises = map(
      createMarkingDefinition,
      sector.markingDefinitions
    );
    await Promise.all(markingDefinitionsPromises);
  }

  await commitWriteTx(wTx);

  return getById(internalId).then(created => {
    return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
  });
};
