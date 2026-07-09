import {
  ingestionTaxiiAdd,
  findTaxiiIngestionPaginated,
  findTaxiiIngestionById,
  ingestionTaxiiDelete,
  ingestionTaxiiEditField,
  ingestionTaxiiResetState,
  ingestionTaxiiAddAutoUser,
  taxiiFeedAddInputFromImport,
  taxiiFeedExport,
} from './ingestion-taxii-domain';
import { removeAuthenticationCredentials } from './ingestion-common';
import { IngestionLogLevel, type Resolvers } from '../../generated/graphql';
import { decryptIngestionCredential } from './ingestion-common';
import { loadCreator } from '../../database/members';
import { type AuthLogEntry, redisGetIngestionLogHistory } from '../../database/redis';
import type { BasicStoreEntityIngestionTaxii } from './ingestion-types';
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

const logsToLogs = (logs: AuthLogEntry[]) => {
  return logs.map(({ timestamp, level, ...others }) => ({
    timestamp: new Date(timestamp),
    level: levelToLevel(level),
    ...others,
  }));
};

const ingestionTaxiiResolvers: Resolvers = {
  Query: {
    ingestionTaxii: (_, { id }, context) => findTaxiiIngestionById(context, context.user, id),
    ingestionTaxiis: (_, args, context) => findTaxiiIngestionPaginated(context, context.user, args),
    taxiiFeedAddInputFromImport: (_, { file }) => taxiiFeedAddInputFromImport(file),
    ingestionTaxiiLogs: async (_: unknown, { id }: { id: string }) => {
      const entries = await redisGetIngestionLogHistory(id);
      return logsToLogs(entries);
    },
  },
  IngestionTaxii: {
    authentication_value: async (ingestionTaxii) => {
      const decrypted = await decryptIngestionCredential(ingestionTaxii.authentication_value);
      return removeAuthenticationCredentials(ingestionTaxii.authentication_type, decrypted);
    },
    user: (ingestionTaxii, _, context) => loadCreator(context, context.user, ingestionTaxii.user_id),
    toConfigurationExport: (ingestionTaxii) => taxiiFeedExport(ingestionTaxii),
    ingestionLogs: async (ingestionTaxii: BasicStoreEntityIngestionTaxii) => {
      const entries = await redisGetIngestionLogHistory(ingestionTaxii.internal_id);
      return logsToLogs(entries);
    },
  },
  Mutation: {
    ingestionTaxiiAdd: (_, { input }, context) => {
      return ingestionTaxiiAdd(context, context.user, input);
    },
    ingestionTaxiiDelete: (_, { id }, context) => {
      return ingestionTaxiiDelete(context, context.user, id);
    },
    ingestionTaxiiResetState: (_, { id }, context) => {
      return ingestionTaxiiResetState(context, context.user, id);
    },
    ingestionTaxiiFieldPatch: (_, { id, input }, context) => {
      return ingestionTaxiiEditField(context, context.user, id, input);
    },
    ingestionTaxiiAddAutoUser: (_, { id, input }, context) => {
      return ingestionTaxiiAddAutoUser(context, context.user, id, input);
    },
  },
};

export default ingestionTaxiiResolvers;
