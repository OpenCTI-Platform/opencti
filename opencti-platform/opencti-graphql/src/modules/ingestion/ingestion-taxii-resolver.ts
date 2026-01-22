import {
  addIngestion,
  findTaxiiIngestionPaginated,
  findById,
  ingestionDelete,
  ingestionEditField,
  ingestionTaxiiResetState,
  ingestionTaxiiAddAutoUser,
  taxiiFeedAddInputFromImport,
  taxiiFeedExport,
} from './ingestion-taxii-domain';
import type { Resolvers } from '../../generated/graphql';

const ingestionTaxiiResolvers: Resolvers = {
  Query: {
    ingestionTaxii: (_, { id }, context) => findById(context, context.user, id, true),
    ingestionTaxiis: (_, args, context) => findTaxiiIngestionPaginated(context, context.user, args),
    taxiiFeedAddInputFromImport: (_, { file }) => taxiiFeedAddInputFromImport(file),
  },
  IngestionTaxii: {
    user: (ingestionTaxii, _, context) => context.batch.creatorBatchLoader.load(ingestionTaxii.user_id),
    toConfigurationExport: (ingestionTaxii) => taxiiFeedExport(ingestionTaxii),
  },
  Mutation: {
    ingestionTaxiiAdd: (_, { input }, context) => {
      return addIngestion(context, context.user, input);
    },
    ingestionTaxiiDelete: (_, { id }, context) => {
      return ingestionDelete(context, context.user, id);
    },
    ingestionTaxiiResetState: (_, { id }, context) => {
      return ingestionTaxiiResetState(context, context.user, id);
    },
    ingestionTaxiiFieldPatch: (_, { id, input }, context) => {
      return ingestionEditField(context, context.user, id, input);
    },
    ingestionTaxiiAddAutoUser: (_, { id, input }, context) => {
      return ingestionTaxiiAddAutoUser(context, context.user, id, input);
    },
  },
};

export default ingestionTaxiiResolvers;
