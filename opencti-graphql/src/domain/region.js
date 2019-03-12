import { head } from 'ramda';
import uuid from 'uuid/v4';
import {
  deleteByID,
  loadByID,
  dayFormat,
  monthFormat,
  yearFormat,
  notify,
  now,
  paginate,
  qk,
  prepareString
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';

export const findAll = args => paginate('match $m isa Region', args);

export const findById = regionId => loadByID(regionId);

export const markingDefinitions = (regionId, args) =>
  paginate(
    `match $marking isa Marking-Definition; 
    $rel(marking:$marking, so:$region) isa object_marking_refs; 
    $region id ${regionId}`,
    args
  );

export const addRegion = async (user, region) => {
  const createRegion = qk(`insert $region isa Region 
    has type "region";
    $region has stix_id "region--${uuid()}";
    $region has stix_label "";
    $region has stix_label_lowercase "";
    $region has alias "";
    $region has alias_lowercase "";
    $region has name "${prepareString(region.name)}";
    $region has description "${prepareString(region.description)}";
    $region has name_lowercase "${prepareString(region.name.toLowerCase())}";
    $region has description_lowercase "${
      region.description ? prepareString(region.description.toLowerCase()) : ''
    }";
    $region has created ${now()};
    $region has modified ${now()};
    $region has revoked false;
    $region has created_at ${now()};
    $region has created_at_day "${dayFormat(now())}";
    $region has created_at_month "${monthFormat(now())}";
    $region has created_at_year "${yearFormat(now())}";
    $region has updated_at ${now()};
  `);
  return createRegion.then(result => {
    const { data } = result;
    return loadByID(head(data).region.id).then(created =>
      notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user)
    );
  });
};

export const regionDelete = regionId => deleteByID(regionId);
