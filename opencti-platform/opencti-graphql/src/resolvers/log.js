import { auditsDistribution, auditsMultiTimeSeries, auditsNumber, auditsTimeSeries, findAudits, findHistory, logsWorkerConfig } from '../domain/log';
import { storeLoadById } from '../database/middleware-loader';
import { ENTITY_TYPE_EXTERNAL_REFERENCE } from '../schema/stixMetaObject';
import { logFrontend } from '../config/conf';
import { filterMembersUsersWithUsersOrgs } from '../utils/access';

const logResolvers = {
  Query: {
    logs: (_, args, context) => findHistory(context, context.user, args),
    audits: (_, args, context) => findAudits(context, context.user, args),
    auditsNumber: (_, args, context) => auditsNumber(context, context.user, args),
    auditsTimeSeries: (_, args, context) => auditsTimeSeries(context, context.user, args),
    auditsMultiTimeSeries: (_, args, context) => auditsMultiTimeSeries(context, context.user, args),
    auditsDistribution: (_, args, context) => auditsDistribution(context, context.user, args),
    logsWorkerConfig: () => logsWorkerConfig(),
  },
  Log: {
    user: async (log, _, context) => {
      const realUser = await context.batch.creatorBatchLoader.load(log.applicant_id || log.user_id);
      if (!realUser) {
        return null;
      }
      const filteredUser = await filterMembersUsersWithUsersOrgs(context, context.user, [realUser]);
      return filteredUser[0];
    },
    context_data: (log, _) => (log.context_data?.id ? { ...log.context_data, entity_id: log.context_data.id } : log.context_data),
    raw_data: (log, _, __) => JSON.stringify(log, null, 2),
    context_uri: (log, _, __) => (log.context_data.id && log.entity_type === 'History' ? `/dashboard/id/${log.context_data.id}` : undefined),
    event_status: (log, _, __) => log.event_status ?? 'success',
    event_scope: (log, _, __) => log.event_scope ?? log.event_type, // Retro compatibility
  },
  ContextData: {
    external_references: (data, _, context) => {
      const refPromises = Promise.all(
        (data.references || []).map((id) => storeLoadById(context, context.user, id, ENTITY_TYPE_EXTERNAL_REFERENCE)),
      ).then((refs) => refs.filter((element) => element !== undefined));
      return Promise.resolve(data.external_references ?? [])
        .then((externalReferences) => refPromises.then((refs) => externalReferences.concat(refs)));
    },
  },
  Mutation: {
    frontendErrorLog: (_, { message, codeStack, componentStack }, __) => {
      logFrontend.error(message, { codeStack, componentStack });
    },
  },
};

export default logResolvers;
