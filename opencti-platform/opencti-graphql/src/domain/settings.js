import { getHeapStatistics } from 'v8';
import { createEntity, loadById, updateAttribute, loadEntity } from '../database/middleware';
import { booleanConf, BUS_TOPICS, PLATFORM_VERSION } from '../config/conf';
import { delEditContext, getRedisVersion, notify, setEditContext } from '../database/redis';
import { elVersion } from '../database/elasticSearch';
import { getRabbitMQVersion } from '../database/rabbitmq';
import { getMinIOVersion } from '../database/minio';
import { ENTITY_TYPE_SETTINGS } from '../schema/internalObject';
import { SYSTEM_USER } from '../utils/access';

export const getMemoryStatistics = () => {
  return { ...process.memoryUsage(), ...getHeapStatistics() };
};

export const getModules = () => {
  const modules = [];
  modules.push({ id: 'GRAPHQL_API', enable: booleanConf('app:enabled', true) });
  modules.push({ id: 'EXPIRATION_SCHEDULER', enable: booleanConf('expiration_scheduler:enabled', false) });
  modules.push({ id: 'TASK_MANAGER', enable: booleanConf('task_scheduler:enabled', false) });
  modules.push({ id: 'RULE_ENGINE', enable: booleanConf('rule_engine:enabled', false) });
  return modules;
};

export const getApplicationInfo = () => ({
  version: PLATFORM_VERSION,
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
