import type { Resolvers } from '../../../generated/graphql';
import { findAll, findById } from './jsonMapper-domain';
import { getJsonMapperErrorMessage } from './jsonMapper-utils';

const jsonMapperResolvers: Resolvers = {
  Query: {
    jsonMapper: (_, { id }, context) => findById(context, context.user, id),
    jsonMappers: (_, args, context) => findAll(context, context.user, args),
  },
  JsonMapper: {
    errors: (jsonMapper, _, context) => getJsonMapperErrorMessage(context, context.user, jsonMapper),
    representations: (_jsonMapper, _, _context) => [],
    toConfigurationExport: (_jsonMapper, _, _context) => '',
  },
};

export default jsonMapperResolvers;
