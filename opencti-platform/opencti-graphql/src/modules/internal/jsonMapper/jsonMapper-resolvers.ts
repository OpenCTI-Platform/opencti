import type { Resolvers } from '../../../generated/graphql';
import { deleteJsonMapper, findAll, findById, jsonMapperExport, jsonMapperImport } from './jsonMapper-domain';
import { getJsonMapperErrorMessage } from './jsonMapper-utils';

const jsonMapperResolvers: Resolvers = {
  Query: {
    jsonMapper: (_, { id }, context) => findById(context, context.user, id),
    jsonMappers: (_, args, context) => findAll(context, context.user, args),
  },
  JsonMapper: {
    errors: (jsonMapper, _, context) => getJsonMapperErrorMessage(context, context.user, jsonMapper),
    representations: (_jsonMapper, _, _context) => [],
    toConfigurationExport: (jsonMapper, _, context) => jsonMapperExport(context, context.user, jsonMapper),
  },
  Mutation: {
    jsonMapperImport: (_, { file }, context) => {
      return jsonMapperImport(context, context.user, file);
    },
    jsonMapperDelete: (_, { id }, context) => {
      return deleteJsonMapper(context, context.user, id);
    },
  }
};

export default jsonMapperResolvers;
