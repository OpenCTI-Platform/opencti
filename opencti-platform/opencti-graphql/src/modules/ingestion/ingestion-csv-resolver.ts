import type { Resolvers } from '../../generated/graphql';
import {
  addIngestionCsv,
  csvFeedAddInputFromImport,
  csvFeedGetCsvMapper,
  csvFeedGetNewDuplicatedCsvMapper,
  csvFeedMapperExport,
  defaultIngestionGroupsCount,
  deleteIngestionCsv,
  findCsvIngestionPaginated,
  findById,
  ingestionCsvAddAutoUser,
  ingestionCsvEditField,
  ingestionCsvResetState,
  testCsvIngestionMapping,
} from './ingestion-csv-domain';
import { userAlreadyExists } from '../user/user-domain';

const ingestionCsvResolvers: Resolvers = {
  Query: {
    ingestionCsv: (_, { id }, context) => findById(context, context.user, id, true),
    ingestionCsvs: (_, args, context) => findCsvIngestionPaginated(context, context.user, args),
    csvFeedAddInputFromImport: (_, { file }, context) => csvFeedAddInputFromImport(context, context.user, file),
    defaultIngestionGroupCount: (_, __, context) => defaultIngestionGroupsCount(context),
    userAlreadyExists: (_, { name }, context) => userAlreadyExists(context, name)
  },
  IngestionCsv: {
    user: (ingestionCsv, _, context) => context.batch.creatorBatchLoader.load(ingestionCsv.user_id),
    csvMapper: (ingestionCsv, _, context) => csvFeedGetCsvMapper(context, context.user, ingestionCsv),
    toConfigurationExport: (ingestionCsv, _, context) => csvFeedMapperExport(context, context.user, ingestionCsv),
    duplicateCsvMapper: (ingestionCsv, _, context) => csvFeedGetNewDuplicatedCsvMapper(context, context.user, ingestionCsv),
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
    ingestionCsvAddAutoUser: (_, { id, input }, context) => {
      return ingestionCsvAddAutoUser(context, context.user, id, input);
    },
  },
};

export default ingestionCsvResolvers;
