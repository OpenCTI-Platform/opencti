import { findAll, logsWorkerConfig } from '../domain/log';
import { findById } from '../domain/user';

const logResolvers = {
  Query: {
    logs: (_, args) => findAll(args),
    logsWorkerConfig: () => logsWorkerConfig(),
  },
  Log: {
    user: (log) => findById(log.user_id),
  },
  LogsFilter: {
    entity_id: 'context_data.id',
    connection_id: 'context_data.*_id',
  },
};

export default logResolvers;
