import type { Resolvers } from '../../../generated/graphql';
import { createCsvMapper, csvMapperTest, deleteCsvMapper, fieldPatchCsvMapper, findAll, findById, csvMapperSchemaAttributes, getParsedRepresentations } from './csvMapper-domain';
import { getCsvMapperErrorMessage } from './csvMapper-utils';

const csvMapperResolvers: Resolvers = {
  Query: {
    csvMapper: (_, { id }, context) => findById(context, context.user, id),
    csvMappers: (_, args, context) => findAll(context, context.user, args),
    csvMapperSchemaAttributes: (_, __, context) => csvMapperSchemaAttributes(context, context.user),
  },
  CsvMapper: {
    errors: (csvMapper, _, context) => getCsvMapperErrorMessage(context, context.user, csvMapper),
    representations: (csvMapper, _, context) => getParsedRepresentations(context, context.user, csvMapper)
  },
  Mutation: {
    csvMapperAdd: (_, { input }, context) => {
      return createCsvMapper(context, context.user, input);
    },
    csvMapperDelete: (_, { id }, context) => {
      return deleteCsvMapper(context, context.user, id);
    },
    csvMapperTest: (_, { configuration, file }, context) => {
      return csvMapperTest(context, context.user, configuration, file);
    },
    csvMapperFieldPatch: (_, { id, input }, context) => {
      return fieldPatchCsvMapper(context, context.user, id, input);
    },
  }
};

export default csvMapperResolvers;
