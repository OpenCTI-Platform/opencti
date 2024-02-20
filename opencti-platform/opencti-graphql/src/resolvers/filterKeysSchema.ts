import { generateFilterKeysSchema } from '../domain/filterKeysSchema';

const filterKeysSchemaResolver = {
  Query: {
    filterKeysSchema: () => generateFilterKeysSchema(),
  },
};

export default filterKeysSchemaResolver;
