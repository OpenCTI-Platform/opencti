import type { ModuleDescriptor } from '../module-descriptor';
import { ORGANIZATION_DEFINITION } from './organization';
import organizationTypeDefs from './organization.graphql';
import organizationResolvers from './organization-resolver';

const organizationModule: ModuleDescriptor = {
  id: 'organization',
  dataModel: [ORGANIZATION_DEFINITION],
  graphqlSchemas: [{ schema: organizationTypeDefs, resolver: organizationResolvers }],
};

export default organizationModule;
