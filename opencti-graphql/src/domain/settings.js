import { head } from 'ramda';
import { delEditContext, setEditContext } from '../database/redis';
import {
  createRelation,
  deleteByID,
  editInputTx,
  loadByID,
  notify,
  now,
  qk
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';

export const findById = settingsId => loadByID(settingsId);

export const addSettings = async (user, settings) => {
  const createSettings = qk(`insert $settings isa Settings 
    has type "settings";
    $settings has platform_title "${settings.platform_title}";
    $settings has platform_email "${settings.platform_email}";
    $settings has platform_url "${settings.platform_url}";
    $settings has platform_language "${settings.platform_language}";
    $settings has platform_external_auth "${settings.platform_external_auth}";
    $settings has platform_registration "${settings.platform_registration}";
    $settings has created_at ${now()};
    $settings has updated_at ${now()};
  `);
  return createSettings.then(result => {
    const { data } = result;
    return findById(head(data).settings.id).then(created =>
      notify(BUS_TOPICS.Settings.ADDED_TOPIC, created)
    );
  });
};

export const settingsDelete = settingsId => deleteByID(settingsId);

export const settingsDeleteRelation = relationId => deleteByID(relationId);

export const settingsAddRelation = (settingsId, input) =>
  createRelation(settingsId, input).then(settings =>
    notify(BUS_TOPICS.Settings.EDIT_TOPIC, settings)
  );

export const settingsCleanContext = (user, settingsId) => {
  delEditContext(user, settingsId);
  return findById(settingsId).then(settings =>
    notify(BUS_TOPICS.Settings.EDIT_TOPIC, settings)
  );
};

export const settingsEditContext = (user, settingsId, input) => {
  setEditContext(user, settingsId, input);
  findById(settingsId).then(settings =>
    notify(BUS_TOPICS.Settings.EDIT_TOPIC, settings)
  );
};

export const settingsEditField = (settingsId, input) =>
  editInputTx(settingsId, input).then(settings =>
    notify(BUS_TOPICS.Settings.EDIT_TOPIC, settings)
  );
