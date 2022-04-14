import { findAll, logsTimeSeries, logsWorkerConfig } from '../domain/log';
import { findById } from '../domain/user';
import { SYSTEM_USER } from '../utils/access';
import { storeLoadById } from '../database/middleware';
import { ENTITY_TYPE_EXTERNAL_REFERENCE } from '../schema/stixMetaObject';

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
  ContextData: {
    references: (data, _, { user }) => Promise.all((data.references || []).map((n) => storeLoadById(user, n, ENTITY_TYPE_EXTERNAL_REFERENCE))),
  },
  LogsFilter: {
    entity_id: 'context_data.id',
    connection_id: 'context_data.*_id',
    user_id: '*_id',
  },
};

export default logResolvers;
