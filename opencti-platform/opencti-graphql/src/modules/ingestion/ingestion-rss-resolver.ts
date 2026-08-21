import {
  addIngestion,
  findRssIngestionPaginated,
  findById,
  ingestionDelete,
  ingestionEditField,
  ingestionAddAutoUser,
  ingestionRssResetState,
  rssFeedAddInputFromImport,
  rssFeedExport,
} from './ingestion-rss-domain';
import { IngestionLogLevel, type Resolvers } from '../../generated/graphql';
import { storeLoadByIds } from '../../database/middleware-loader';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../../schema/stixMetaObject';
import type { BasicStoreEntityMarkingDefinition } from '../../types/store';
import { ENTITY_TYPE_IDENTITY } from '../../schema/general';
import { loadCreator } from '../../database/members';
import { type IngestionLogEntry, redisGetIngestionLogHistory } from '../../database/redis';
import type { BasicStoreEntityIngestionRss } from './ingestion-types';
import { DatabaseError } from '../../config/errors';

const levelToLevel = (level: string): IngestionLogLevel => {
  switch (level) {
    case 'success':
      return IngestionLogLevel.Success;
    case 'info':
      return IngestionLogLevel.Info;
    case 'warn':
      return IngestionLogLevel.Warn;
    case 'error':
      return IngestionLogLevel.Error;
    default:
      throw DatabaseError('Unknown ingestion log level', { level });
  }
};

const logsToLogs = (logs: IngestionLogEntry[]) => {
  return logs.map(({ timestamp, level, ...others }) => ({
    timestamp: new Date(timestamp),
    level: levelToLevel(level),
    ...others,
  }));
};

const ingestionRssResolvers: Resolvers = {
  Query: {
    ingestionRss: (_, { id }, context) => findById(context, context.user, id),
    ingestionRsss: (_, args, context) => findRssIngestionPaginated(context, context.user, args),
    ingestionRssAddInputFromImport: (_, { file }) => rssFeedAddInputFromImport(file),
    ingestionRssLogs: async (_: unknown, { id }: { id: string }, context) => {
      await findById(context, context.user, id);
      const entries = await redisGetIngestionLogHistory(id);
      return logsToLogs(entries);
    },
  },
  IngestionRss: {
    defaultCreatedBy: (ingestionRss, _, context) => context.batch.idsBatchLoader.load({ id: ingestionRss.created_by_ref, type: ENTITY_TYPE_IDENTITY }),
    // eslint-disable-next-line max-len
    defaultMarkingDefinitions: (ingestionRss, _, context) => storeLoadByIds<BasicStoreEntityMarkingDefinition>(context, context.user, ingestionRss.object_marking_refs ?? [], ENTITY_TYPE_MARKING_DEFINITION),
    user: (ingestionRss, _, context) => loadCreator(context, context.user, ingestionRss.user_id),
    toConfigurationExport: (ingestionRss, _, context) => rssFeedExport(context, context.user, ingestionRss),
    ingestionLogs: async (ingestionRss: BasicStoreEntityIngestionRss) => {
      const entries = await redisGetIngestionLogHistory(ingestionRss.internal_id);
      return logsToLogs(entries);
    },
  },
  Mutation: {
    ingestionRssAdd: (_, { input }, context) => {
      return addIngestion(context, context.user, input);
    },
    ingestionRssDelete: (_, { id }, context) => {
      return ingestionDelete(context, context.user, id);
    },
    ingestionRssFieldPatch: (_, { id, input }, context) => {
      return ingestionEditField(context, context.user, id, input);
    },
    ingestionRssAddAutoUser: (_, { id, input }, context) => {
      return ingestionAddAutoUser(context, context.user, id, input);
    },
    ingestionRssResetState: (_, { id }, context) => {
      return ingestionRssResetState(context, context.user, id);
    },
  },
};

export default ingestionRssResolvers;
