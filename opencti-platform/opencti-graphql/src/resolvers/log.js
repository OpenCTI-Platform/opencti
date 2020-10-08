import { findAll, logsTimeSeries, logsWorkerConfig } from '../domain/log';
import { findById } from '../domain/user';

const logResolvers = {
  Query: {
    logs: (_, args) => findAll(args),
    logsTimeSeries: (_, args) => logsTimeSeries(args),
    logsWorkerConfig: () => logsWorkerConfig(),
  },
  Log: {
    user: (log) => findById(log.applicant_id || log.user_id),
  },
  LogsFilter: {
    entity_id: 'context_data.id',
    connection_id: 'context_data.*_id',
    user_id: '*_id',
  },
};

export default logResolvers;
