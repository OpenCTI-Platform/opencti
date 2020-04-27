import { findAll, logsWorkerConfig } from '../domain/log';
import { findById } from '../domain/user';

const logResolvers = {
  Query: {
    logs: (_, args) => findAll(args),
    logsWorkerConfig: () => logsWorkerConfig(),
  },
  Log: {
    event_user: (log) => findById(log.event_user),
  },
  LogsFilter: {
    entity_id: 'event_data.x_opencti_id',
    connection_id: 'event_data.x_opencti_*_ref',
  },
};

export default logResolvers;
