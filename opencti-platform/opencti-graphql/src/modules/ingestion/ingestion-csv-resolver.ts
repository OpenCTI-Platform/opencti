import { batchLoader } from '../../database/middleware';
import { batchCreator } from '../../domain/user';
import type { Resolvers } from '../../generated/graphql';
import {
  addIngestionCsv,
  csvFeedAddInputFromImport,
  csvFeedGetCsvMapper,
  csvFeedMapperExport,
  defaultIngestionGroupsCount,
  deleteIngestionCsv,
  findAllPaginated,
  findById,
  ingestionCsvEditField,
  ingestionCsvResetState,
  testCsvIngestionMapping,
  userAlreadyExists
} from './ingestion-csv-domain';

const creatorLoader = batchLoader(batchCreator);

const ingestionCsvResolvers: Resolvers = {
  Query: {
    ingestionCsv: (_, { id }, context) => findById(context, context.user, id),
    ingestionCsvs: (_, args, context) => findAllPaginated(context, context.user, args),
    csvFeedAddInputFromImport: (_, { file }, context) => csvFeedAddInputFromImport(context, context.user, file),
    defaultIngestionGroupCount: (_, __, context) => defaultIngestionGroupsCount(context),
    userAlreadyExists: (_, { name }, context) => userAlreadyExists(context, name)
  },
  IngestionCsv: {
    user: (ingestionCsv, _, context) => creatorLoader.load(ingestionCsv.user_id, context, context.user),
    csvMapper: (ingestionCsv, _, context) => csvFeedGetCsvMapper(context, ingestionCsv),
    toConfigurationExport: (ingestionCsv, _, context) => csvFeedMapperExport(context, context.user, ingestionCsv),
  },
  Mutation: {
    ingestionCsvTester: (_, { input }, context) => {
      return testCsvIngestionMapping(context, context.user, input);
    },
    ingestionCsvAdd: (_, { input }, context) => {
      return addIngestionCsv(context, context.user, input);
    },
    ingestionCsvResetState: (_, { id }, context) => {
      return ingestionCsvResetState(context, context.user, id);
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
