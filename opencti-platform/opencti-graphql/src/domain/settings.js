import { assoc, head } from 'ramda';
import {
  createEntity,
  deleteEntityById,
  executeWrite,
  getGraknVersion,
  listEntities,
  loadEntityById,
  TYPE_OPENCTI_INTERNAL,
  updateAttribute
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { delEditContext, getRedisVersion, notify, setEditContext } from '../database/redis';
import { elVersion } from '../database/elasticSearch';
import { getRabbitMQVersion } from '../database/rabbitmq';
import { getMinIOVersion } from '../database/minio';
import { version } from '../../package.json';

export const getApplicationInfo = () => ({
  version,
  dependencies: [
    { name: 'Grakn', version: getGraknVersion() },
    { name: 'Elasticsearch', version: elVersion() },
    { name: 'RabbitMQ', version: getRabbitMQVersion() },
    { name: 'Redis', version: getRedisVersion() },
    { name: 'MinIO', version: getMinIOVersion() }
  ]
});

export const getSettings = async () => {
  const typedArgs = assoc('types', ['Settings'], {});
  return listEntities(['platform_title'], typedArgs).then(data => head(data.edges).node);
};

export const addSettings = async (user, settings) => {
  const created = await createEntity(settings, 'Settings', { modelType: TYPE_OPENCTI_INTERNAL });
  return notify(BUS_TOPICS.Settings.ADDED_TOPIC, created, user);
};

export const settingsDelete = settingsId => {
  return deleteEntityById(settingsId);
};

export const settingsCleanContext = (user, settingsId) => {
  delEditContext(user, settingsId);
  return loadEntityById(settingsId).then(settings => notify(BUS_TOPICS.Settings.EDIT_TOPIC, settings, user));
};

export const settingsEditContext = (user, settingsId, input) => {
  setEditContext(user, settingsId, input);
  return loadEntityById(settingsId).then(settings => notify(BUS_TOPICS.Settings.EDIT_TOPIC, settings, user));
};

export const settingsEditField = (user, settingsId, input) => {
  return executeWrite(wTx => {
    return updateAttribute(settingsId, input, wTx);
  }).then(async () => {
    const settings = await loadEntityById(settingsId);
    return notify(BUS_TOPICS.Settings.EDIT_TOPIC, settings, user);
  });
};
