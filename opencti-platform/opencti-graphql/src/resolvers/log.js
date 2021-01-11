import { findAll, logsTimeSeries, logsWorkerConfig } from '../domain/log';
import { findById, SYSTEM_USER } from '../domain/user';

const logResolvers = {
  Query: {
    logs: (_, args) => findAll(args),
    logsTimeSeries: (_, args) => logsTimeSeries(args),
    logsWorkerConfig: () => logsWorkerConfig(),
  },
  Log: {
    user: async (log) => {
      const user = await findById(log.applicant_id || log.user_id);
      return user || SYSTEM_USER;
    },
  },
  LogsFilter: {
    entity_id: 'context_data.id',
    connection_id: 'context_data.*_id',
    user_id: '*_id',
  },
};

export default logResolvers;
