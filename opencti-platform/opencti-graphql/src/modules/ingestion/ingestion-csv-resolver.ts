import { batchLoader } from '../../database/middleware';
import { batchCreator } from '../../domain/user';
import type { Resolvers } from '../../generated/graphql';
import { addIngestionCsv, deleteIngestionCsv, findAllPaginated, findById, ingestionCsvEditField, testCsvIngestionMapping } from './ingestion-csv-domain';

const creatorLoader = batchLoader(batchCreator);

const ingestionCsvResolvers: Resolvers = {
  Query: {
    ingestionCsv: (_, { id }, context) => findById(context, context.user, id),
    ingestionCsvs: (_, args, context) => findAllPaginated(context, context.user, args),
    test_mapper: (_, { uri, csvMapper_id }, context) => testCsvIngestionMapping(context, context.user, uri, csvMapper_id),
  },
  IngestionCsv: {
    user: (ingestionCsv, _, context) => creatorLoader.load(ingestionCsv.user_id, context, context.user),
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
