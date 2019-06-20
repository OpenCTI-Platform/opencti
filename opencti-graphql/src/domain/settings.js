import uuid from 'uuid/v4';
import {
  escape,
  escapeString,
  deleteEntityById,
  updateAttribute,
  getById,
  getObject,
  notify,
  now,
  takeWriteTx, commitWriteTx
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
  const internalId = settings.internal_id
    ? escapeString(settings.internal_id)
    : uuid();
  await wTx.tx.query(`insert $settings isa Settings,
    has internal_id "${internalId}",
    has entity_type "settings",
    has platform_title "${escapeString(settings.platform_title)}",
    has platform_email "${escapeString(settings.platform_email)}",
    has platform_url "${escapeString(settings.platform_url)}",
    has platform_language "${escapeString(settings.platform_language)}",
    has platform_external_auth ${escape(settings.platform_external_auth)},
    has platform_registration ${escape(settings.platform_registration)},
    has created_at ${now()},
    has updated_at ${now()};
  `);

  await commitWriteTx(wTx);

  return getById(internalId).then(created =>
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
