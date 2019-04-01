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

export const findAll = args => paginate('match $s isa Sector', args);

export const findById = sectorId => getById(sectorId);

export const markingDefinitions = (sectorId, args) =>
  paginate(
    `match $marking isa Marking-Definition; 
    $rel(marking:$marking, so:$s) isa object_marking_refs; 
    $s id ${sectorId}`,
    args
  );

export const addSector = async (user, sector) => {
  const wTx = await takeWriteTx();
  const sectorIterator = await wTx.query(`insert $sector isa Sector,
    has entity_type "sector",
    has stix_id "${
      sector.stix_id ? prepareString(sector.stix_id) : `sector--${uuid()}`
    }",
    has stix_label "",
    has alias "",
    has name "${prepareString(sector.name)}",
    has description "${prepareString(sector.description)}",
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
    await wTx.query(
      `match $from id ${createdSectorId};
      $to id ${sector.createdByRef};
      insert (so: $from, creator: $to)
      isa created_by_ref;`
    );
  }

  if (sector.markingDefinitions) {
    const createMarkingDefinition = markingDefinition =>
      wTx.query(
        `match $from id ${createdSectorId}; 
        $to id ${markingDefinition};
        insert (so: $from, marking: $to) isa object_marking_refs;`
      );
    const markingDefinitionsPromises = map(
      createMarkingDefinition,
      sector.markingDefinitions
    );
    await Promise.all(markingDefinitionsPromises);
  }

  await wTx.commit();

  return getById(createdSectorId).then(created =>
    notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user)
  );
};

export const sectorDelete = sectorId => deleteEntityById(sectorId);
