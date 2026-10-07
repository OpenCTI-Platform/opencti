import { registerGraphqlSchema } from '../../graphql/schema';
import timelineTypeDefs from './timeline.graphql';
import timelineResolvers from './timeline-resolvers';

registerGraphqlSchema({
  schema: timelineTypeDefs,
  resolver: timelineResolvers,
});
