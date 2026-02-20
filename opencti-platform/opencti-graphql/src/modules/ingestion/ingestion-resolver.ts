import type { Resolvers } from '../../generated/graphql';

import { redisGetConnectorHistory } from '../../database/redis';

const ingestionResolvers: Resolvers = {
  Query: {
    ingestionHistory: (_: unknown, { id }: { id: string }) => redisGetConnectorHistory(id),
  },
};

export default ingestionResolvers;
