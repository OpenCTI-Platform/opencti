import { registerGraphqlSchema } from '../../graphql/schema';
import organizationTypeDefs from './organization.graphql';
import organizationResolvers from './organization-resolver';

registerGraphqlSchema({
  schema: organizationTypeDefs,
  resolver: organizationResolvers,
});
