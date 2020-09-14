import { findAll, logsWorkerConfig } from '../domain/log';
import { findById } from '../domain/user';

const logResolvers = {
  Query: {
    logs: (_, args) => findAll(args),
    logsWorkerConfig: () => logsWorkerConfig(),
  },
  Log: {
    user: (log) => findById(log.user),
  },
  LogsFilter: {
    entity_id: 'data.x_opencti_id',
    connection_id: 'data.*_ref',
  },
};

export default logResolvers;
