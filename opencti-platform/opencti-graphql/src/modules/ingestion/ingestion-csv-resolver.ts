import { batchLoader } from '../../database/middleware';
import { batchCreator } from '../../domain/user';
import type { Resolvers } from '../../generated/graphql';
import { addIngestionCsv, deleteIngestionCsv, findAllPaginated, findById, ingestionCsvEditField, testCsvIngestionMapping } from './ingestion-csv-domain';

const creatorLoader = batchLoader(batchCreator);

const ingestionCsvResolvers: Resolvers = {
  Query: {
    ingestionCsv: (_, { id }, context) => findById(context, context.user, id),
    ingestionCsvs: (_, args, context) => findAllPaginated(context, context.user, args),
  },
  IngestionCsv: {
    user: (ingestionCsv, _, context) => creatorLoader.load(ingestionCsv.user_id, context, context.user),
    test_mapper: (ingestionCsv, _, context) => testCsvIngestionMapping(context, ingestionCsv),
  },
  Mutation: {
    ingestionCsvAdd: (_, { input }, context) => {
      return addIngestionCsv(context, context.user, input);
    },
    ingestionCsvDelete: (_, { id }, context) => {
      return deleteIngestionCsv(context, context.user, id);
    },
    ingestionCsvFieldPatch: (_, { id, input }, context) => {
      return ingestionCsvEditField(context, context.user, id, input);
    },
  },
};

export default ingestionCsvResolvers;
