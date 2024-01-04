import { registerGraphqlSchema } from '../../../graphql/schema';
import feedbackTypeDefs from './feedback.graphql';
import feedbackResolvers from './feedback-resolvers';

registerGraphqlSchema({
  schema: feedbackTypeDefs,
  resolver: feedbackResolvers,
});
