import { generateFilterKeysSchema } from '../domain/filterKeysSchema';
import type { AuthContext } from '../types/user';

const filterKeysSchemaResolver = {
  Query: {
    filterKeysSchema: (_: unknown, __: unknown, context: AuthContext) => generateFilterKeysSchema(context.user ? { context, user: context.user } : undefined),
  },
};

export default filterKeysSchemaResolver;
