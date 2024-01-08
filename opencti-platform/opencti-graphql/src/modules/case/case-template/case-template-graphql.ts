import { registerGraphqlSchema } from '../../../graphql/schema';
import caseTemplateTypeDefs from './case-template.graphql';
import caseTemplateResolvers from './case-template-resolvers';

registerGraphqlSchema({
  schema: caseTemplateTypeDefs,
  resolver: caseTemplateResolvers,
});
