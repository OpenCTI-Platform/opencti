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

export const findAll = args => paginate('match $m isa Region', args);

export const findById = regionId => getById(regionId);

export const markingDefinitions = (regionId, args) =>
  paginate(
    `match $marking isa Marking-Definition; 
    $rel(marking:$marking, so:$region) isa object_marking_refs; 
    $region id ${regionId}`,
    args
  );

export const addRegion = async (user, region) => {
  const wTx = await takeWriteTx();
  const regionIterator = await wTx.query(`insert $region isa Region 
    has type "region";
    $region has stix_id "${
      region.stix_id ? prepareString(region.stix_id) : `region--${uuid()}`
    }";
    $region has stix_label "";
    $region has alias "";
    $region has name "${prepareString(region.name)}";
    $region has description "${prepareString(region.description)}";
    $region has created ${region.created ? prepareDate(region.created) : now()};
    $region has modified ${region.modified ? prepareDate(region.modified) : now()};
    $region has revoked false;
    $region has created_at ${now()};
    $region has created_at_day "${dayFormat(now())}";
    $region has created_at_month "${monthFormat(now())}";
    $region has created_at_year "${yearFormat(now())}";
    $region has updated_at ${now()};
  `);
  const createRegion = await regionIterator.next();
  const createdRegionId = await createRegion.map().get('region').id;

  if (region.createdByRef) {
    await wTx.query(`match $from id ${createdRegionId};
         $to id ${region.createdByRef};
         insert (so: $from, creator: $to)
         isa created_by_ref;`);
  }

  if (region.markingDefinitions) {
    const createMarkingDefinition = markingDefinition =>
      wTx.query(
        `match $from id ${createdRegionId}; $to id ${markingDefinition}; insert (so: $from, marking: $to) isa object_marking_refs;`
      );
    const markingDefinitionsPromises = map(
      createMarkingDefinition,
      region.markingDefinitions
    );
    await Promise.all(markingDefinitionsPromises);
  }

  await wTx.commit();

  return getById(createdRegionId).then(created =>
    notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user)
  );
};

export const regionDelete = regionId => deleteEntityById(regionId);
