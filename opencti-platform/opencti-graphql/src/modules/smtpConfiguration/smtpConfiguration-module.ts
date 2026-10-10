import type { ModuleDescriptor } from '../module-descriptor';
import smtpConfigurationTypeDefs from './smtpConfiguration.graphql';
import smtpConfigurationResolvers from './smtpConfiguration-resolver';

const smtpConfigurationModule: ModuleDescriptor = {
  id: 'smtpConfiguration',
  graphqlSchemas: [{ schema: smtpConfigurationTypeDefs, resolver: smtpConfigurationResolvers }],
};

export default smtpConfigurationModule;
