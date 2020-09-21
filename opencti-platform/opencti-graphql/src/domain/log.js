import { head } from 'ramda';
import { elPaginate, INDEX_HISTORY } from '../database/elasticSearch';
import conf from '../config/conf';
import { amqpUri, EVENT_TYPE_CREATE } from '../database/rabbitmq';
import { findById, SYSTEM_USER } from './user';
import { ABSTRACT_STIX_CORE_OBJECT, OPENCTI_ADMIN_UUID } from '../schema/general';
import { loadById } from '../database/grakn';

export const findAll = (args) => elPaginate(INDEX_HISTORY, args);

export const creator = async (entityId) => {
  const entity = await loadById(entityId, ABSTRACT_STIX_CORE_OBJECT);
  return elPaginate(INDEX_HISTORY, {
    filters: [
      { key: 'event_type', values: [EVENT_TYPE_CREATE] },
      { key: 'context_data.id', values: [entity.internal_id] },
    ],
    connectionFormat: false,
  }).then((logs) =>
    logs.length > 0 && head(logs).user_id
      ? findById(head(logs).user_id)
      : { id: OPENCTI_ADMIN_UUID, name: SYSTEM_USER.name }
  );
};

export const logsWorkerConfig = () => ({
  elasticsearch_url: conf.get('elasticsearch:url'),
  elasticsearch_index: INDEX_HISTORY,
  rabbitmq_url: amqpUri(),
});
