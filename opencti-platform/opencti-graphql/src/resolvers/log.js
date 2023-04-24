import { findHistory, findAudits, logsTimeSeries, logsWorkerConfig } from '../domain/log';
import { batchCreator } from '../domain/user';
import { storeLoadById } from '../database/middleware-loader';
import { ENTITY_TYPE_EXTERNAL_REFERENCE } from '../schema/stixMetaObject';
import { batchLoader } from '../database/middleware';

const creatorLoader = batchLoader(batchCreator);

const logResolvers = {
  Query: {
    logs: (_, args, context) => findHistory(context, context.user, args),
    audits: (_, args, context) => findAudits(context, context.user, args),
    logsTimeSeries: (_, args, context) => logsTimeSeries(context, context.user, args),
    logsWorkerConfig: () => logsWorkerConfig(),
  },
  Log: {
    user: (log, _, context) => creatorLoader.load(log.applicant_id || log.user_id, context, context.user),
    raw_data: (log, _, __) => JSON.stringify(log, null, 2),
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
    elementId: 'context_data.id',
    connection_id: 'context_data.*_id',
    user_id: 'user_id',
    creator: 'user_id',
    group: 'group_ids',
    organization: 'organization_ids',
    created: 'timestamp',
  },
};

export default logResolvers;
