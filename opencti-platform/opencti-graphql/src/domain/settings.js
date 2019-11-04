import uuid from 'uuid/v4';
import {
  deleteEntityById,
  escape,
  escapeString,
  executeWrite,
  refetchEntityById,
  getGraknVersion,
  getObject,
  graknNow,
  notify,
  updateAttribute
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import {
  delEditContext,
  getRedisVersion,
  setEditContext
} from '../database/redis';

import { getElasticVersion, loadById } from '../database/elasticSearch';

import { getRabbitMQVersion } from '../database/rabbitmq';
import { version } from '../../package.json';

export const getApplicationInfo = () => ({
  version,
  dependencies: [
    { name: 'Grakn', version: getGraknVersion() },
    { name: 'Elasticsearch', version: getElasticVersion() },
    { name: 'RabbitMQ', version: getRabbitMQVersion() },
    { name: 'Redis', version: getRedisVersion() }
    // TODO Add Minio
  ]
});

export const getSettings = () =>
  getObject(
    `match $x isa Settings; 
    get; 
    offset 0; 
    limit 1;`
  ).then(result => result.node);

export const addSettings = async (user, settings) => {
  const settingId = await executeWrite(async wTx => {
    const internalId = settings.internal_id_key
      ? escapeString(settings.internal_id_key)
      : uuid();
    await wTx.tx.query(`insert $settings isa Settings,
    has internal_id_key "${internalId}",
    has entity_type "settings",
    has platform_title "${escapeString(settings.platform_title)}",
    has platform_email "${escapeString(settings.platform_email)}",
    has platform_url "${escapeString(settings.platform_url)}",
    has platform_language "${escapeString(settings.platform_language)}",
    has platform_external_auth ${escape(settings.platform_external_auth)},
    has platform_registration ${escape(settings.platform_registration)},
    has created_at ${graknNow()},
    has updated_at ${graknNow()};
  `);
    return internalId;
  });
  return refetchEntityById(settingId).then(created =>
    notify(BUS_TOPICS.Settings.ADDED_TOPIC, created, user)
  );
};

export const settingsDelete = settingsId => deleteEntityById(settingsId);

export const settingsCleanContext = (user, settingsId) => {
  delEditContext(user, settingsId);
  return refetchEntityById(settingsId).then(settings =>
    notify(BUS_TOPICS.Settings.EDIT_TOPIC, settings, user)
  );
};

export const settingsEditContext = (user, settingsId, input) => {
  setEditContext(user, settingsId, input);
  return refetchEntityById(settingsId).then(settings =>
    notify(BUS_TOPICS.Settings.EDIT_TOPIC, settings, user)
  );
};

export const settingsEditField = (user, settingsId, input) => {
  return executeWrite(wTx => {
    return updateAttribute(settingsId, input, wTx);
  }).then(async () => {
    const settings = await loadById(settingsId);
    return notify(BUS_TOPICS.Settings.EDIT_TOPIC, settings, user);
  });
};
