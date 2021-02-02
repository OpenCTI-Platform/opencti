import { findAll, logsTimeSeries, logsWorkerConfig } from '../domain/log';
import { findById, SYSTEM_USER } from '../domain/user';

const logResolvers = {
  Query: {
    logs: (_, args, { user }) => findAll(user, args),
    logsTimeSeries: (_, args, { user }) => logsTimeSeries(user, args),
    logsWorkerConfig: () => logsWorkerConfig(),
  },
  Log: {
    user: async (log, _, { user }) => {
      const findUser = await findById(user, log.applicant_id || log.user_id);
      return findUser || SYSTEM_USER;
    },
  },
  LogsFilter: {
    entity_id: 'context_data.id',
    connection_id: 'context_data.*_id',
    user_id: '*_id',
  },
};

export default logResolvers;
