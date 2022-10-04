import { findAll, logsTimeSeries, logsWorkerConfig } from '../domain/log';
import { findById } from '../domain/user';
import { SYSTEM_USER } from '../utils/access';
import { storeLoadById } from '../database/middleware';
import { ENTITY_TYPE_EXTERNAL_REFERENCE } from '../schema/stixMetaObject';

const logResolvers = {
  Query: {
    logs: (_, args, context) => findAll(context, context.user, args),
    logsTimeSeries: (_, args, context) => logsTimeSeries(context, context.user, args),
    logsWorkerConfig: () => logsWorkerConfig(),
  },
  Log: {
    user: async (log, _, context) => {
      const findUser = await findById(context, context.user, log.applicant_id || log.user_id);
      return findUser || SYSTEM_USER;
    },
  },
  ContextData: {
    references: (data, _, context) => Promise.all((data.references || [])
      .map((n) => storeLoadById(context, context.user, n, ENTITY_TYPE_EXTERNAL_REFERENCE))),
  },
  LogsFilter: {
    entity_id: 'context_data.id',
    connection_id: 'context_data.*_id',
    user_id: '*_id',
  },
};

export default logResolvers;
