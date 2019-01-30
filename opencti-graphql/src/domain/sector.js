import { map } from 'ramda';
import uuid from 'uuid/v4';
import {
  deleteByID,
  loadByID,
  monthFormat,
  notify,
  now,
  paginate,
  takeTx,
  yearFormat
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';

export const findAll = args => paginate('match $m isa Sector', args);

export const findById = sectorId => loadByID(sectorId);

export const markingDefinitions = (sectorId, args) =>
  paginate(
    `match $marking isa Marking-Definition; 
    $rel(marking:$marking, so:$sector) isa object_marking_refs; 
    $sector id ${sectorId}`,
    args
  );

export const addSector = async (user, sector) => {
  const wTx = await takeTx();
  const sectorIterator = await wTx.query(`insert $sector isa Sector 
    has type "sector";
    $sector has stix_id "sector--${uuid()}";
    $sector has stix_label "";
    $sector has stix_label_lowercase "";
    $sector has alias "";
    $sector has alias_lowercase "";
    $sector has name "${sector.name}";
    $sector has description "${sector.description}";
    $sector has name_lowercase "${sector.name.toLowerCase()}";
    $sector has description_lowercase "${
      sector.description ? sector.description.toLowerCase() : ''
    }";
    $sector has created ${now()};
    $sector has modified ${now()};
    $sector has revoked false;
    $sector has created_at ${now()};
    $sector has created_at_month "${monthFormat(now())}";
    $sector has created_at_year "${yearFormat(now())}";       
    $sector has updated_at ${now()};
  `);
  const createSector = await sectorIterator.next();
  const createdSectorId = await createSector.map().get('sector').id;

  if (sector.createdByRef) {
    await wTx.query(`match $from id ${createdSectorId};
         $to id ${sector.createdByRef};
         insert (so: $from, creator: $to)
         isa created_by_ref;`);
  }

  if (sector.markingDefinitions) {
    const createMarkingDefinition = markingDefinition =>
      wTx.query(
        `match $from id ${createdSectorId}; $to id ${markingDefinition}; insert (so: $from, marking: $to) isa object_marking_refs;`
      );
    const markingDefinitionsPromises = map(
      createMarkingDefinition,
      sector.markingDefinitions
    );
    await Promise.all(markingDefinitionsPromises);
  }

  await wTx.commit();

  return loadByID(createdSectorId).then(created =>
    notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user)
  );
};

export const sectorDelete = sectorId => deleteByID(sectorId);
