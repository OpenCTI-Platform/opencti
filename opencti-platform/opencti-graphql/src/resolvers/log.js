import { findAll, logsTimeSeries, logsWorkerConfig } from '../domain/log';
import { batchCreator } from '../domain/user';
import { storeLoadById } from '../database/middleware-loader';
import { ENTITY_TYPE_EXTERNAL_REFERENCE } from '../schema/stixMetaObject';
import { batchLoader } from '../database/middleware';

const creatorLoader = batchLoader(batchCreator);

const logResolvers = {
  Query: {
    logs: (_, args, context) => findAll(context, context.user, args),
    logsTimeSeries: (_, args, context) => logsTimeSeries(context, context.user, args),
    logsWorkerConfig: () => logsWorkerConfig(),
  },
  Log: {
    user: (log, _, context) => creatorLoader.load(log.applicant_id || log.user_id, context, context.user),
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
