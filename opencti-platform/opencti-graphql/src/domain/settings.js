import { getHeapStatistics } from 'v8';
import { createEntity, loadById, updateAttribute, loadEntity } from '../database/middleware';
import { BUS_TOPICS } from '../config/conf';
import { delEditContext, getRedisVersion, notify, setEditContext } from '../database/redis';
import { elVersion } from '../database/elasticSearch';
import { getRabbitMQVersion } from '../database/rabbitmq';
import { getMinIOVersion } from '../database/minio';
import pjson from '../../package.json';
import { ENTITY_TYPE_SETTINGS } from '../schema/internalObject';
import { SYSTEM_USER } from './user';

export const getMemoryStatistics = () => {
  return { ...process.memoryUsage(), ...getHeapStatistics() };
};

export const getApplicationInfo = () => ({
  version: pjson.version,
  memory: getMemoryStatistics(),
  dependencies: [
    { name: 'Elasticsearch', version: elVersion() },
    { name: 'RabbitMQ', version: getRabbitMQVersion() },
    { name: 'Redis', version: getRedisVersion() },
    { name: 'MinIO', version: getMinIOVersion() },
  ],
});

export const getSettings = async () => {
  return loadEntity(SYSTEM_USER, [ENTITY_TYPE_SETTINGS]);
};

export const addSettings = async (user, settings) => {
  const created = await createEntity(user, settings, ENTITY_TYPE_SETTINGS);
  return notify(BUS_TOPICS.Settings.ADDED_TOPIC, created, user);
};

export const settingsCleanContext = (user, settingsId) => {
  delEditContext(user, settingsId);
  return loadById(user, settingsId, ENTITY_TYPE_SETTINGS).then((settings) =>
    notify(BUS_TOPICS.Settings.EDIT_TOPIC, settings, user)
  );
};

export const settingsEditContext = (user, settingsId, input) => {
  setEditContext(user, settingsId, input);
  return loadById(user, settingsId, ENTITY_TYPE_SETTINGS).then((settings) =>
    notify(BUS_TOPICS.Settings.EDIT_TOPIC, settings, user)
  );
};

export const settingsEditField = async (user, settingsId, input) => {
  const settings = await updateAttribute(user, settingsId, ENTITY_TYPE_SETTINGS, input);
  return notify(BUS_TOPICS.Settings.EDIT_TOPIC, settings, user);
};
