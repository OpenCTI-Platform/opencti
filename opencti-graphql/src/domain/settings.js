import {
  deleteEntityById,
  updateAttribute,
  getById,
  getObject,
  notify,
  now,
  takeWriteTx,
  prepareString
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { delEditContext, setEditContext } from '../database/redis';

export const getSettings = () =>
  getObject(
    `match $x isa Settings; 
    get; 
    offset 0; 
    limit 1;`
  ).then(result => result.node);

export const addSettings = async (user, settings) => {
  const wTx = await takeWriteTx();
  const settingsIterator = await wTx.query(`insert $settings isa Settings,
    has entity_type "settings",
    has platform_title "${prepareString(settings.platform_title)}",
    has platform_email "${prepareString(settings.platform_email)}",
    has platform_url "${prepareString(settings.platform_url)}",
    has platform_language "${prepareString(settings.platform_language)}",
    has platform_external_auth ${settings.platform_external_auth},
    has platform_registration ${settings.platform_registration},
    has created_at ${now()},
    has updated_at ${now()};
  `);
  const createSettings = await settingsIterator.next();
  const createdSettingsId = await createSettings.map().get('settings').id;

  await wTx.commit();

  return getById(createdSettingsId).then(created =>
    notify(BUS_TOPICS.Settings.ADDED_TOPIC, created, user)
  );
};

export const settingsDelete = settingsId => deleteEntityById(settingsId);

export const settingsCleanContext = (user, settingsId) => {
  delEditContext(user, settingsId);
  return getById(settingsId).then(settings =>
    notify(BUS_TOPICS.Settings.EDIT_TOPIC, settings, user)
  );
};

export const settingsEditContext = (user, settingsId, input) => {
  setEditContext(user, settingsId, input);
  return getById(settingsId).then(settings =>
    notify(BUS_TOPICS.Settings.EDIT_TOPIC, settings, user)
  );
};

export const settingsEditField = (user, settingsId, input) =>
  updateAttribute(settingsId, input).then(settings =>
    notify(BUS_TOPICS.Settings.EDIT_TOPIC, settings, user)
  );
