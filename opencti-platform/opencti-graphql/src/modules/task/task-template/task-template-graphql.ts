import { registerGraphqlSchema } from '../../../graphql/schema';
import caseTaskTypeDefs from './task-template.graphql';
import taskTemplateResolvers from './task-template-resolvers';

registerGraphqlSchema({
  schema: caseTaskTypeDefs,
  resolver: taskTemplateResolvers,
});
