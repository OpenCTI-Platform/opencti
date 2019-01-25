import { head } from 'ramda';
import uuid from 'uuid/v4';
import { delEditContext, setEditContext } from '../database/redis';
import {
  createRelation,
  deleteByID,
  deleteRelation,
  editInputTx,
  loadByID,
  notify,
  now,
  paginate,
  qk
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
  const createSector = qk(`insert $sector isa Sector 
    has type "sector";
    $sector has stix_id "sector--${uuid()}";
    $sector has stix_label "";
    $sector has stix_label_lowercase "";
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
    $sector has updated_at ${now()};
  `);
  return createSector.then(result => {
    const { data } = result;
    return loadByID(head(data).sector.id).then(created =>
      notify(BUS_TOPICS.Sector.ADDED_TOPIC, created, user)
    );
  });
};

export const sectorDelete = sectorId => deleteByID(sectorId);

export const sectorAddRelation = (user, sectorId, input) =>
  createRelation(sectorId, input).then(relationData => {
    notify(BUS_TOPICS.Sector.EDIT_TOPIC, relationData.node, user);
    return relationData;
  });

export const sectorDeleteRelation = (user, sectorId, relationId) =>
  deleteRelation(sectorId, relationId).then(relationData => {
    notify(BUS_TOPICS.Sector.EDIT_TOPIC, relationData.node, user);
    return relationData;
  });

export const sectorCleanContext = (user, sectorId) => {
  delEditContext(user, sectorId);
  return loadByID(sectorId).then(sector =>
    notify(BUS_TOPICS.Sector.EDIT_TOPIC, sector, user)
  );
};

export const sectorEditContext = (user, sectorId, input) => {
  setEditContext(user, sectorId, input);
  return loadByID(sectorId).then(sector =>
    notify(BUS_TOPICS.Sector.EDIT_TOPIC, sector, user)
  );
};

export const sectorEditField = (user, sectorId, input) =>
  editInputTx(sectorId, input).then(sector =>
    notify(BUS_TOPICS.Sector.EDIT_TOPIC, sector, user)
  );
