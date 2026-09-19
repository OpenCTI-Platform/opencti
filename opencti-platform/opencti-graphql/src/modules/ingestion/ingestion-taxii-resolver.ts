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
import { findIngestionLogsForFeed, removeAuthenticationCredentials } from './ingestion-common';
import type { Resolvers } from '../../generated/graphql';
import { decryptIngestionCredential } from './ingestion-common';
import { loadCreator } from '../../database/members';
import type { BasicStoreEntityIngestionTaxii } from './ingestion-types';

const ingestionTaxiiResolvers: Resolvers = {
  Query: {
    ingestionTaxii: (_, { id }, context) => findTaxiiIngestionById(context, context.user, id),
    ingestionTaxiis: (_, args, context) => findTaxiiIngestionPaginated(context, context.user, args),
    taxiiFeedAddInputFromImport: (_, { file }) => taxiiFeedAddInputFromImport(file),
    ingestionTaxiiLogs: async (_: unknown, { id }: { id: string }, context) => {
      await findTaxiiIngestionById(context, context.user, id);
      return findIngestionLogsForFeed(id);
    },
  },
  IngestionTaxii: {
    authentication_value: async (ingestionTaxii) => {
      const decrypted = await decryptIngestionCredential(ingestionTaxii.authentication_value);
      return removeAuthenticationCredentials(ingestionTaxii.authentication_type, decrypted);
    },
    user: (ingestionTaxii, _, context) => loadCreator(context, context.user, ingestionTaxii.user_id),
    toConfigurationExport: (ingestionTaxii) => taxiiFeedExport(ingestionTaxii),
    ingestionLogs: (ingestionTaxii: BasicStoreEntityIngestionTaxii) => findIngestionLogsForFeed(ingestionTaxii.internal_id),
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
