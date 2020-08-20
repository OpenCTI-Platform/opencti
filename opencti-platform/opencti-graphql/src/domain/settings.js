import { assoc, dissocPath, pipe } from 'ramda';
import { createEntity, executeWrite, getGraknVersion, load, loadEntityById, updateAttribute } from '../database/grakn';
import conf, { BUS_TOPICS } from '../config/conf';
import { delEditContext, getRedisVersion, notify, setEditContext } from '../database/redis';
import { elVersion } from '../database/elasticSearch';
import { getRabbitMQVersion } from '../database/rabbitmq';
import { getMinIOVersion } from '../database/minio';
import { version } from '../../package.json';
import { ENTITY_TYPE_SETTINGS } from '../schema/internalObject';

export const getApplicationInfo = () => ({
  version,
  dependencies: [
    { name: 'Grakn', version: getGraknVersion() },
    { name: 'Elasticsearch', version: elVersion() },
    { name: 'RabbitMQ', version: getRabbitMQVersion() },
    { name: 'Redis', version: getRedisVersion() },
    { name: 'MinIO', version: getMinIOVersion() },
  ],
});

export const getSettings = async () => {
  const query = `match $settings isa ${ENTITY_TYPE_SETTINGS}; $settings has internal_id $settings_id; get;`;
  const data = await load(query, ['settings']);
  const settings = data && data.settings;
  if (settings == null) return null;
  const config = pipe(
    dissocPath(['app', 'admin']),
    dissocPath(['rabbitmq', 'password']),
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
  const created = await createEntity(user, settings, ENTITY_TYPE_SETTINGS, { noLog: true });
  return notify(BUS_TOPICS.Settings.ADDED_TOPIC, created, user);
};

export const settingsCleanContext = (user, settingsId) => {
  delEditContext(user, settingsId);
  return loadEntityById(settingsId, ENTITY_TYPE_SETTINGS).then((settings) =>
    notify(BUS_TOPICS.Settings.EDIT_TOPIC, settings, user)
  );
};

export const settingsEditContext = (user, settingsId, input) => {
  setEditContext(user, settingsId, input);
  return loadEntityById(settingsId, ENTITY_TYPE_SETTINGS).then((settings) =>
    notify(BUS_TOPICS.Settings.EDIT_TOPIC, settings, user)
  );
};

export const settingsEditField = (user, settingsId, input) => {
  return executeWrite((wTx) => {
    return updateAttribute(user, settingsId, ENTITY_TYPE_SETTINGS, input, wTx, { noLog: true });
  }).then(async () => {
    const settings = await loadEntityById(settingsId, ENTITY_TYPE_SETTINGS);
    return notify(BUS_TOPICS.Settings.EDIT_TOPIC, settings, user);
  });
};
