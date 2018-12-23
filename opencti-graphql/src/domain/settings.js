import { head } from 'ramda';
import {
  deleteByID,
  editInputTx,
  loadByID,
  loadFirst,
  notify,
  now,
  qk
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { delEditContext, setEditContext } from '../database/redis';

export const getSettings = () => loadFirst('Settings').then(result => result);

export const addSettings = async (user, settings) => {
  const createSettings = qk(`insert $settings isa Settings 
    has platform_title "${settings.platform_title}";
    $settings has platform_email "${settings.platform_email}";
    $settings has platform_url "${settings.platform_url}";
    $settings has platform_language "${settings.platform_language}";
    $settings has platform_external_auth ${settings.platform_external_auth};
    $settings has platform_registration ${settings.platform_registration};
    $settings has created_at ${now()};
    $settings has updated_at ${now()};
  `);
  return createSettings.then(result => {
    const { data } = result;
    return loadByID(head(data).settings.id).then(created =>
      notify(BUS_TOPICS.Settings.ADDED_TOPIC, created, user)
    );
  });
};

export const settingsDelete = settingsId => deleteByID(settingsId);

export const settingsCleanContext = (user, settingsId) => {
  delEditContext(user, settingsId);
  return loadByID(settingsId).then(settings =>
    notify(BUS_TOPICS.Settings.EDIT_TOPIC, settings, user)
  );
};

export const settingsEditContext = (user, settingsId, input) => {
  setEditContext(user, settingsId, input);
  loadByID(settingsId).then(settings =>
    notify(BUS_TOPICS.Settings.EDIT_TOPIC, settings, user)
  );
};

export const settingsEditField = (user, settingsId, input) =>
  editInputTx(settingsId, input).then(settings =>
    notify(BUS_TOPICS.Settings.EDIT_TOPIC, settings, user)
  );
