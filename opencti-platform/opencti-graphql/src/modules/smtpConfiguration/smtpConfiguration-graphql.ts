import { registerGraphqlSchema } from '../../graphql/schema';
import smtpConfigurationTypeDefs from './smtpConfiguration.graphql';
import smtpConfigurationResolvers from './smtpConfiguration-resolver';

registerGraphqlSchema({
  schema: smtpConfigurationTypeDefs,
  resolver: smtpConfigurationResolvers,
});
