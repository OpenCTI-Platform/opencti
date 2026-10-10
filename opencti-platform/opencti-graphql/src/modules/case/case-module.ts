import type { ModuleDescriptor } from '../module-descriptor';
import { CASE_DEFINITION } from './case';
import caseTypeDefs from './case.graphql';
import caseResolvers from './case-resolvers';

const caseModule: ModuleDescriptor = {
  id: 'case',
  dataModel: [CASE_DEFINITION],
  graphqlSchemas: [{ schema: caseTypeDefs, resolver: caseResolvers }],
};

export default caseModule;
