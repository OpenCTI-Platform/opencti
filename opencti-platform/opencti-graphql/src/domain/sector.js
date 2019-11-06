import { assoc, head, join, map, tail } from 'ramda';
import uuid from 'uuid/v4';
import {
  dayFormat,
  escapeString,
  executeWrite,
  loadEntityById,
  getSingleValueNumber,
  graknNow,
  monthFormat,
  paginate,
  prepareDate,
  yearFormat
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { elPaginate } from '../database/elasticSearch';
import { linkCreatedByRef, linkMarkingDef } from './stixEntity';
import { notify } from '../database/redis';

export const findAll = args => {
  return elPaginate('stix_domain_entities', assoc('type', 'sector', args));
};

export const findById = sectorId => loadEntityById(sectorId);

export const markingDefinitions = (sectorId, args) => {
  return paginate(
    `match $marking isa Marking-Definition; 
    $rel(marking:$marking, so:$s) isa object_marking_refs; 
    $s has internal_id_key "${escapeString(sectorId)}"`,
    args
  );
};

export const subsectors = (sectorId, args) => {
  return paginate(
    `match $subsector isa Sector; 
    $rel(gather:$s, part_of:$subsector) isa gathering; 
    $s has internal_id_key "${escapeString(sectorId)}"`,
    args
  );
};

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
  const sectorId = await executeWrite(async wTx => {
    const internalId = sector.internal_id_key
      ? escapeString(sector.internal_id_key)
      : uuid();
    const sectorIterator = await wTx.tx.query(`insert $sector isa Sector,
    has internal_id_key "${internalId}",
    has entity_type "sector",
    has stix_id_key "${
      sector.stix_id_key
        ? escapeString(sector.stix_id_key)
        : `identity--${uuid()}`
    }",
    has stix_label "",
    has stix_label "",
    ${
      sector.alias
        ? `${join(
            ' ',
            map(val => `has alias "${escapeString(val)}",`, tail(sector.alias))
          )} has alias "${escapeString(head(sector.alias))}",`
        : 'has alias "",'
    }
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

    // Create associated relations
    await linkCreatedByRef(wTx, createdSectorId, sector.createdByRef);
    await linkMarkingDef(wTx, createdSectorId, sector.markingDefinitions);
    return internalId;
  });
  return loadEntityById(sectorId).then(created => {
    return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
  });
};
