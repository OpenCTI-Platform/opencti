import { findAll, logsTimeSeries, logsWorkerConfig } from '../domain/log';
import { findById } from '../domain/user';
import { RETENTION_MANAGER_USER, RULE_MANAGER_USER, SYSTEM_USER } from '../utils/access';
import { storeLoadById } from '../database/middleware-loader';
import { ENTITY_TYPE_EXTERNAL_REFERENCE } from '../schema/stixMetaObject';

const logResolvers = {
  Query: {
    logs: (_, args, context) => findAll(context, context.user, args),
    logsTimeSeries: (_, args, context) => logsTimeSeries(context, context.user, args),
    logsWorkerConfig: () => logsWorkerConfig(),
  },
  Log: {
    user: async (log, _, context) => {
      const userId = log.applicant_id || log.user_id;
      if (userId === SYSTEM_USER.id) return SYSTEM_USER;
      if (userId === RULE_MANAGER_USER.id) return RULE_MANAGER_USER;
      if (userId === RETENTION_MANAGER_USER.id) return RETENTION_MANAGER_USER;
      const findUser = await findById(context, context.user, userId);
      return findUser || SYSTEM_USER;
    },
  },
  // Backward compatibility
  ContextData: {
    external_references: (data, _, context) => {
      const refPromises = Promise.all(
        (data.references || []).map((id) => storeLoadById(context, context.user, id, ENTITY_TYPE_EXTERNAL_REFERENCE))
      ).then((refs) => refs.filter((element) => element !== undefined));

      return Promise.resolve(data.external_references ?? [])
        .then((externalReferences) => refPromises.then((refs) => externalReferences.concat(refs)));
    }
  },
  LogsFilter: {
    entity_id: 'context_data.id',
    connection_id: 'context_data.*_id',
    user_id: '*_id',
  },
};

export default logResolvers;
