import { assoc, dissocPath, pipe } from 'ramda';
import { getHeapStatistics } from 'v8';
import { createEntity, loadById, updateAttribute, listEntities } from '../database/middleware';
import conf, { BUS_TOPICS } from '../config/conf';
import { delEditContext, getRedisVersion, notify, setEditContext } from '../database/redis';
import { elVersion } from '../database/elasticSearch';
import { getRabbitMQVersion } from '../database/rabbitmq';
import { getMinIOVersion } from '../database/minio';
import { version } from '../../package.json';
import { ENTITY_TYPE_SETTINGS } from '../schema/internalObject';

export const getMemoryStatistics = () => {
  return { ...process.memoryUsage(), ...getHeapStatistics() };
};

export const getApplicationInfo = () => ({
  version,
  memory: getMemoryStatistics(),
  dependencies: [
    { name: 'Elasticsearch', version: elVersion() },
    { name: 'RabbitMQ', version: getRabbitMQVersion() },
    { name: 'Redis', version: getRedisVersion() },
    { name: 'MinIO', version: getMinIOVersion() },
  ],
});

export const getSettings = async () => {
  const settingsList = await listEntities([ENTITY_TYPE_SETTINGS]);
  const settings = settingsList.edges.length > 0 ? settingsList.edges[0].node : null;
  if (settings === null) return null;
  const config = pipe(
    dissocPath(['app', 'admin']),
    dissocPath(['rabbitmq', 'password']),
    dissocPath(['elasticsearch', 'url']),
    dissocPath(['minio', 'access_key']),
    dissocPath(['minio', 'secret_key']),
    dissocPath(['jwt']),
    dissocPath(['providers', 'ldap', 'config', 'bind_credentials']),
    dissocPath(['providers', 'google', 'config', 'client_secret']),
    dissocPath(['providers', 'facebook', 'config', 'client_secret']),
    dissocPath(['providers', 'github', 'config', 'client_secret']),
    dissocPath(['providers', 'openid', 'config', 'client_secret'])
  )(conf.get());
  return assoc('platform_parameters', JSON.stringify(config), settings);
};

export const addSettings = async (user, settings) => {
  const created = await createEntity(user, settings, ENTITY_TYPE_SETTINGS);
  return notify(BUS_TOPICS.Settings.ADDED_TOPIC, created, user);
};

export const settingsCleanContext = (user, settingsId) => {
  delEditContext(user, settingsId);
  return loadById(settingsId, ENTITY_TYPE_SETTINGS).then((settings) =>
    notify(BUS_TOPICS.Settings.EDIT_TOPIC, settings, user)
  );
};

export const settingsEditContext = (user, settingsId, input) => {
  setEditContext(user, settingsId, input);
  return loadById(settingsId, ENTITY_TYPE_SETTINGS).then((settings) =>
    notify(BUS_TOPICS.Settings.EDIT_TOPIC, settings, user)
  );
};

export const settingsEditField = async (user, settingsId, input) => {
  const settings = await updateAttribute(user, settingsId, ENTITY_TYPE_SETTINGS, input);
  return notify(BUS_TOPICS.Settings.EDIT_TOPIC, settings, user);
};
