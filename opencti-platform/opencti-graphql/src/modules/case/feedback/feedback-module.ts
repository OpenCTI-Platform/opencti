import type { ModuleDescriptor } from '../../module-descriptor';
import { FEEDBACK_DEFINITION } from './feedback';
import feedbackTypeDefs from './feedback.graphql';
import feedbackResolvers from './feedback-resolvers';

const feedbackModule: ModuleDescriptor = {
  id: 'feedback',
  dataModel: [FEEDBACK_DEFINITION],
  graphqlSchemas: [{ schema: feedbackTypeDefs, resolver: feedbackResolvers }],
};

export default feedbackModule;
