import { findAll, logsWorkerConfig } from '../domain/log';

const logResolvers = {
  Query: {
    logs: (_, args) => findAll(args),
    logsWorkerConfig: () => logsWorkerConfig(),
  },
  LogsFilter: {
    entity_id: 'event_data.x_opencti_id',
    connection_id: 'event_data.x_opencti_*_ref',
  },
};

export default logResolvers;
